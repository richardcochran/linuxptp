// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <linux/if_ether.h>

#include "address.h"
#include "dpdk_glue.h"
#include "ether.h"

#ifdef PTP4D_HAVE_DPDK

#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define DPDK_RX_RING_SIZE 1024
#define DPDK_TX_RING_SIZE 1024
#define DPDK_NUM_MBUFS 8192
#define DPDK_MBUF_CACHE_SIZE 250
#define DPDK_BURST_SIZE 32

struct dpdk_glue_ctx {
	int initialized;
	int eal_initialized;
	int poll_fd;
	enum rte_proc_type_t proc_type;
	uint16_t port_id;
	uint16_t rxq;
	uint16_t txq;
	struct rte_mempool *pool;
	uint8_t src_mac[MAC_LEN];
};

static struct dpdk_glue_ctx g = {
	.initialized = 0,
	.poll_fd = -1,
};

static const uint8_t ptp_dst_primary[MAC_LEN] = {
	0x01, 0x1B, 0x19, 0x00, 0x00, 0x00
};
static const uint8_t ptp_dst_pdelay[MAC_LEN] = {
	0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E
};

static int64_t wallclock_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts))
		return 1;
	return (int64_t) ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int64_t timespec_ns(const struct timespec *ts)
{
	return (int64_t) ts->tv_sec * 1000000000LL + ts->tv_nsec;
}

static int create_poll_timerfd(void)
{
	struct itimerspec it;
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (fd < 0)
		return -1;

	memset(&it, 0, sizeof(it));
	it.it_interval.tv_nsec = 1000000;
	it.it_value.tv_nsec = 1000000;

	if (timerfd_settime(fd, 0, &it, NULL) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static void drain_poll_timerfd(int fd)
{
	uint64_t expirations;

	if (fd < 0)
		return;
	if (read(fd, &expirations, sizeof(expirations)) < 0) {
		if (errno == EAGAIN)
			return;
	}
}

static int ifname_to_pci_addr(const char *ifname, char *pci_addr, size_t len)
{
	char dev_link[PATH_MAX];
	char resolved[PATH_MAX];
	char *base;
	ssize_t n;

	if (!ifname || !ifname[0])
		return -1;

	if (snprintf(dev_link, sizeof(dev_link), "/sys/class/net/%s/device",
			     ifname) >= (int) sizeof(dev_link)) {
		return -1;
	}

	n = readlink(dev_link, resolved, sizeof(resolved) - 1);
	if (n <= 0)
		return -1;
	resolved[n] = '\0';

	base = strrchr(resolved, '/');
	if (!base || !base[1])
		return -1;
	base++;

	if (snprintf(pci_addr, len, "%s", base) >= (int) len)
		return -1;

	return 0;
}

static int ifname_to_mac_addr(const char *ifname, struct rte_ether_addr *mac)
{
	char path[PATH_MAX];
	FILE *f;
	unsigned int b[MAC_LEN];

	if (!ifname || !ifname[0] || !mac)
		return -1;
	if (snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname) >=
	    (int) sizeof(path)) {
		return -1;
	}
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fscanf(f, "%x:%x:%x:%x:%x:%x",
		   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != MAC_LEN) {
		fclose(f);
		return -1;
	}
	fclose(f);
	mac->addr_bytes[0] = b[0];
	mac->addr_bytes[1] = b[1];
	mac->addr_bytes[2] = b[2];
	mac->addr_bytes[3] = b[3];
	mac->addr_bytes[4] = b[4];
	mac->addr_bytes[5] = b[5];
	return 0;
}

static void dump_dpdk_ports(const char *ifname)
{
	struct rte_ether_addr mac;
	char name[RTE_ETH_NAME_MAX_LEN];
	uint16_t pid;

	fprintf(stderr, "dpdk: resolve failed for ifname=%s; discovered ports:\n",
		ifname ? ifname : "");
	RTE_ETH_FOREACH_DEV(pid) {
		if (rte_eth_dev_get_name_by_port(pid, name))
			snprintf(name, sizeof(name), "<unknown>");
		rte_eth_macaddr_get(pid, &mac);
		fprintf(stderr,
			"dpdk:   port=%u name=%s mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
			pid, name,
			mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
			mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
	}
}

static int resolve_port_id(const char *ifname, uint16_t *port_id)
{
	char pci_addr[64];
	struct rte_ether_addr target_mac;
	struct rte_ether_addr mac;
	int has_target_mac = 0;
	uint16_t pid;
	uint16_t n_ports;

	if (ifname && ifname[0]) {
		has_target_mac = (ifname_to_mac_addr(ifname, &target_mac) == 0);

		if (rte_eth_dev_get_port_by_name(ifname, port_id) == 0)
			return 0;

		if (ifname_to_pci_addr(ifname, pci_addr, sizeof(pci_addr)) == 0) {
			if (rte_eth_dev_get_port_by_name(pci_addr, port_id) == 0)
				return 0;

			RTE_ETH_FOREACH_DEV(pid) {
				char name[RTE_ETH_NAME_MAX_LEN];

				if (!rte_eth_dev_get_name_by_port(pid, name) &&
				    !strcmp(name, pci_addr)) {
					*port_id = pid;
					return 0;
				}
			}
		}

		if (!has_target_mac && ifname_to_pci_addr(ifname, pci_addr,
						 sizeof(pci_addr)) == 0) {
			char path[PATH_MAX];
			FILE *f;
			unsigned int b[MAC_LEN];

			if (snprintf(path, sizeof(path),
				"/sys/bus/pci/devices/%s/net/%s/address", pci_addr,
				ifname) < (int) sizeof(path)) {
				f = fopen(path, "r");
				if (f) {
					if (fscanf(f, "%x:%x:%x:%x:%x:%x", &b[0], &b[1],
						   &b[2], &b[3], &b[4], &b[5]) == MAC_LEN) {
						target_mac.addr_bytes[0] = b[0];
						target_mac.addr_bytes[1] = b[1];
						target_mac.addr_bytes[2] = b[2];
						target_mac.addr_bytes[3] = b[3];
						target_mac.addr_bytes[4] = b[4];
						target_mac.addr_bytes[5] = b[5];
						has_target_mac = 1;
					}
					fclose(f);
				}
			}
		}

		if (has_target_mac) {
			RTE_ETH_FOREACH_DEV(pid) {
				rte_eth_macaddr_get(pid, &mac);
				if (rte_is_same_ether_addr(&mac, &target_mac)) {
					*port_id = pid;
					return 0;
				}
			}
		}

		if (rte_eth_dev_count_avail() == 1) {
			RTE_ETH_FOREACH_DEV(pid) {
				*port_id = pid;
				return 0;
			}
		}

		return -1;
	}

	n_ports = rte_eth_dev_count_avail();
	if (!n_ports)
		return -1;
	*port_id = 0;
	return 0;
}

static int init_mempool(void)
{
	char pool_name[64];

	snprintf(pool_name, sizeof(pool_name), "ptp4d_dpdk_pool_%d", getpid());
	g.pool = rte_mempool_lookup(pool_name);
	if (g.pool)
		return 0;
	g.pool = rte_pktmbuf_pool_create(pool_name,
			DPDK_NUM_MBUFS,
			DPDK_MBUF_CACHE_SIZE,
			0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (!g.pool) {
		errno = ENOMEM;
		return -1;
	}
	return 0;
}

static int init_dpdk_port(const char *ifname)
{
	struct rte_eth_conf conf;
	struct rte_ether_addr mac;
	static const char * const eal_argv[] = { "ptp4l", "--proc-type=auto", NULL };
	char port_name[RTE_ETH_NAME_MAX_LEN] = {0};
	int argc = 2;
	int rc;

	if (g.initialized)
		return 0;

	if (!g.eal_initialized) {
		rc = rte_eal_init(argc, (char **) eal_argv);
		if (rc < 0) {
			if (rte_errno != EALREADY) {
				errno = EIO;
				return -1;
			}
		}
		g.eal_initialized = 1;
	}
	g.proc_type = rte_eal_process_type();

	if (resolve_port_id(ifname, &g.port_id)) {
		dump_dpdk_ports(ifname);
		errno = ENODEV;
		return -1;
	}
	(void) ifname;
	(void) port_name;

	g.rxq = 0;
	g.txq = 0;
	memset(&conf, 0, sizeof(conf));

	conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
	conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP;

	if (init_mempool())
		return -1;

	if (g.proc_type == RTE_PROC_PRIMARY) {
		rc = rte_eth_dev_configure(g.port_id, 1, 1, &conf);
		if (rc < 0) {
			errno = EIO;
			return -1;
		}

		rc = rte_eth_rx_queue_setup(g.port_id, g.rxq,
				DPDK_RX_RING_SIZE, rte_eth_dev_socket_id(g.port_id),
				NULL, g.pool);
		if (rc < 0) {
			errno = EIO;
			return -1;
		}

		rc = rte_eth_tx_queue_setup(g.port_id, g.txq,
				DPDK_TX_RING_SIZE, rte_eth_dev_socket_id(g.port_id),
				NULL);
		if (rc < 0) {
			errno = EIO;
			return -1;
		}

		rc = rte_eth_dev_start(g.port_id);
		if (rc < 0) {
			errno = EIO;
			return -1;
		}

		rte_eth_timesync_enable(g.port_id);

		rte_eth_promiscuous_enable(g.port_id);
		rte_eth_allmulticast_enable(g.port_id);
	}

	rte_eth_macaddr_get(g.port_id, &mac);
	memcpy(g.src_mac, mac.addr_bytes, MAC_LEN);

	g.poll_fd = create_poll_timerfd();
	if (g.poll_fd < 0) {
		errno = EIO;
		return -1;
	}

	g.initialized = 1;
	return 0;
}

static int parse_ptp_payload(struct rte_mbuf *m, void *buf, int buflen,
			     struct address *addr)
{
	uint8_t *pkt;
	int plen;
	int hdr_len;
	uint16_t ether_type;

	plen = rte_pktmbuf_pkt_len(m);
	if (plen < (int) sizeof(struct eth_hdr))
		return -1;

	pkt = rte_pktmbuf_mtod(m, uint8_t *);
	hdr_len = sizeof(struct eth_hdr);

	ether_type = rte_be_to_cpu_16(*(uint16_t *)(pkt + 2 * MAC_LEN));
	if (ether_type == ETH_P_8021Q && plen >= (int) sizeof(struct vlan_hdr)) {
		hdr_len = sizeof(struct vlan_hdr);
		ether_type =
			rte_be_to_cpu_16(*(uint16_t *)(pkt + sizeof(struct vlan_hdr) - 2));
	}
	if (ether_type != ETH_P_1588)
		return -1;

	if (plen - hdr_len > buflen) {
		errno = EMSGSIZE;
		return -1;
	}

	memcpy(buf, pkt + hdr_len, plen - hdr_len);

	if (addr) {
		memset(addr, 0, sizeof(*addr));
		addr->sll.sll_family = AF_PACKET;
		addr->sll.sll_halen = MAC_LEN;
		memcpy(addr->sll.sll_addr, pkt + MAC_LEN, MAC_LEN);
		addr->len = sizeof(addr->sll);
	}

	return plen - hdr_len;
}

static void set_rx_hwts(struct rte_mbuf *m, struct dpdk_hw_timestamp *hwts)
{
	struct timespec ts;

	(void) m;

	if (!hwts)
		return;
	hwts->sw = nanoseconds_to_tmv(wallclock_ns());
	if (!rte_eth_timesync_read_rx_timestamp(g.port_id, &ts, 0)) {
		hwts->ts = nanoseconds_to_tmv(timespec_ns(&ts));
		return;
	}
	hwts->ts = hwts->sw;
}

int
ptp_dpdk_open(const char *ifname, enum timestamp_type tt, int *poll_fd)
{
	(void) tt;

	if (!poll_fd) {
		errno = EINVAL;
		return -1;
	}
	if (init_dpdk_port(ifname))
		return -1;
	*poll_fd = g.poll_fd;
	return 0;
}

int ptp_dpdk_close(void)
{
	int eal_initialized;

	if (!g.initialized)
		return 0;
	eal_initialized = g.eal_initialized;
	if (g.poll_fd >= 0) {
		close(g.poll_fd);
		g.poll_fd = -1;
	}
	if (g.proc_type == RTE_PROC_PRIMARY) {
		rte_eth_dev_stop(g.port_id);
		rte_eth_dev_close(g.port_id);
	}
	memset(&g, 0, sizeof(g));
	g.eal_initialized = eal_initialized;
	g.poll_fd = -1;
	return 0;
}

int
ptp_dpdk_recv(void *buf, int buflen, struct address *addr,
		      struct hw_timestamp *hwts)
{
	struct rte_mbuf *pkts[DPDK_BURST_SIZE];
	uint16_t n;
	uint16_t i;
	int cnt;

	if (!g.initialized) {
		errno = ENODEV;
		return -1;
	}
	drain_poll_timerfd(g.poll_fd);

	n = rte_eth_rx_burst(g.port_id, g.rxq, pkts, DPDK_BURST_SIZE);
	if (!n) {
		errno = EAGAIN;
		return -1;
	}

	for (i = 0; i < n; i++) {
		cnt = parse_ptp_payload(pkts[i], buf, buflen, addr);
		if (cnt >= 0) {
			set_rx_hwts(pkts[i], hwts);
			rte_pktmbuf_free(pkts[i]);
			for (i = i + 1; i < n; i++)
				rte_pktmbuf_free(pkts[i]);
			return cnt;
		}
		rte_pktmbuf_free(pkts[i]);
	}

	errno = EAGAIN;
	return -1;
}

int
ptp_dpdk_send(enum transport_event event, int peer, void *buf,
		      int buflen, struct address *addr,
		      struct hw_timestamp *hwts)
{
	struct rte_mbuf *m;
	uint8_t *pkt;
	struct eth_hdr *eh;
	uint16_t len;
	uint16_t sent;

	(void) event;

	if (!g.initialized) {
		errno = ENODEV;
		return -1;
	}

	m = rte_pktmbuf_alloc(g.pool);
	if (!m) {
		errno = ENOMEM;
		return -1;
	}

	len = sizeof(struct eth_hdr) + buflen;
	pkt = (uint8_t *) rte_pktmbuf_append(m, len);
	if (!pkt) {
		rte_pktmbuf_free(m);
		errno = EMSGSIZE;
		return -1;
	}

	eh = (struct eth_hdr *) pkt;
	if (addr && addr->sll.sll_halen == MAC_LEN)
		memcpy(eh->dst, addr->sll.sll_addr, MAC_LEN);
	else
		memcpy(eh->dst, peer ? ptp_dst_pdelay : ptp_dst_primary, MAC_LEN);
	memcpy(eh->src, g.src_mac, MAC_LEN);
	eh->type = rte_cpu_to_be_16(ETH_P_1588);
	memcpy(pkt + sizeof(struct eth_hdr), buf, buflen);

	sent = rte_eth_tx_burst(g.port_id, g.txq, &m, 1);
	if (sent != 1) {
		rte_pktmbuf_free(m);
		errno = EIO;
		return -1;
	}

	if (hwts) {
		struct timespec ts;

		hwts->sw = nanoseconds_to_tmv(wallclock_ns());
		if (!rte_eth_timesync_read_tx_timestamp(g.port_id, &ts))
			hwts->ts = nanoseconds_to_tmv(timespec_ns(&ts));
		else
			hwts->ts = hwts->sw;
	}

	return buflen;
}

int ptp_dpdk_physical_addr(uint8_t *addr)
{
	if (!g.initialized || !addr)
		return 0;
	memcpy(addr, g.src_mac, MAC_LEN);
	return MAC_LEN;
}

int ptp_dpdk_protocol_addr(uint8_t *addr)
{
	return ptp_dpdk_physical_addr(addr);
}

#else

int
ptp_dpdk_open(const char *ifname, enum timestamp_type tt, int *poll_fd)
{
	(void) ifname;
	(void) tt;

	if (!poll_fd) {
		errno = EINVAL;
		return -1;
	}

	*poll_fd = -1;
	errno = ENOTSUP;
	return -1;
}

int ptp_dpdk_close(void)
{
	return 0;
}

int
ptp_dpdk_recv(void *buf, int buflen, struct address *addr,
		      struct hw_timestamp *hwts)
{
	(void) buf;
	(void) buflen;
	(void) addr;

	if (hwts)
		memset(hwts, 0, sizeof(*hwts));

	errno = EAGAIN;
	return -1;
}

int
ptp_dpdk_send(enum transport_event event, int peer, void *buf,
		      int buflen, struct address *addr,
		      struct hw_timestamp *hwts)
{
	(void) event;
	(void) peer;
	(void) buf;
	(void) buflen;
	(void) addr;
	(void) hwts;

	errno = ENOTSUP;
	return -1;
}

int ptp_dpdk_physical_addr(uint8_t *addr)
{
	(void) addr;
	return 0;
}

int ptp_dpdk_protocol_addr(uint8_t *addr)
{
	(void) addr;
	return 0;
}

#endif

