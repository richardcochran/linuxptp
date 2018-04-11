/**
 * @file sk.c
 * @brief Implements protocol independent socket methods.
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <errno.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <poll.h>

#include "address.h"
#include "ether.h"
#include "missing.h"
#include "print.h"
#include "sk.h"

/* globals */

int sk_tx_timeout = 1;
int sk_check_fupsync;
int sk_high_res = 0;

/* private methods */

static int hwts_init(int fd, const char *device, int rx_filter, int tx_type)
{
	struct ifreq ifreq;
	struct hwtstamp_config cfg, req;
	int err;

	memset(&ifreq, 0, sizeof(ifreq));
	memset(&cfg, 0, sizeof(cfg));

	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

	ifreq.ifr_data = (void *) &cfg;
	cfg.tx_type    = tx_type;
	cfg.rx_filter  = rx_filter;
	req = cfg;
	err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
	// HACK - SIOCHWTSTAMP is not passed through the ieee802154 layer
	//if (err < 0)
	//return err;
	(void) err;

	if (memcmp(&cfg, &req, sizeof(cfg))) {

		pr_debug("driver changed our HWTSTAMP options");
		pr_debug("tx_type   %d not %d", cfg.tx_type, req.tx_type);
		pr_debug("rx_filter %d not %d", cfg.rx_filter, req.rx_filter);

		if (cfg.tx_type != req.tx_type ||
		    (cfg.rx_filter != HWTSTAMP_FILTER_ALL &&
		     cfg.rx_filter != HWTSTAMP_FILTER_PTP_V2_EVENT)) {
			return -1;
		}
	}

	return 0;
}

/* public methods */

int sk_interface_fd(void)
{
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("socket failed: %m");
		return -1;
	}
	return fd;
}

int sk_interface_index(int fd, const char *name)
{
	struct ifreq ifreq;
	int err;

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);
	err = ioctl(fd, SIOCGIFINDEX, &ifreq);
	if (err < 0) {
		pr_err("ioctl SIOCGIFINDEX failed: %m");
		return err;
	}
	return ifreq.ifr_ifindex;
}

int sk_general_init(int fd)
{
	int on = sk_check_fupsync ? 1 : 0;
	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on)) < 0) {
		pr_err("ioctl SO_TIMESTAMPNS failed: %m");
		return -1;
	}
	return 0;
}

int sk_get_ts_info(const char *name, struct sk_ts_info *sk_info)
{
#ifdef ETHTOOL_GET_TS_INFO
	struct ethtool_ts_info info;
	struct ifreq ifr;
	int fd, err;

	memset(&ifr, 0, sizeof(ifr));
	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_GET_TS_INFO;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_data = (char *) &info;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0) {
		pr_err("socket failed: %m");
		goto failed;
	}

	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err < 0) {
		pr_err("ioctl SIOCETHTOOL failed: %m");
		close(fd);
		goto failed;
	}

	close(fd);

	/* copy the necessary data to sk_info */
	memset(sk_info, 0, sizeof(struct sk_ts_info));
	sk_info->valid = 1;
	sk_info->phc_index = info.phc_index;
	sk_info->so_timestamping = info.so_timestamping;
	sk_info->tx_types = info.tx_types;
	sk_info->rx_filters = info.rx_filters;
	// HACK - SIOCETHTOOL is not passed through the ieee802154 layer
	sk_info->phc_index = 0;
	sk_info->so_timestamping = (SOF_TIMESTAMPING_TX_HARDWARE |
				    SOF_TIMESTAMPING_RX_HARDWARE |
				    SOF_TIMESTAMPING_RAW_HARDWARE);

	return 0;
failed:
#endif
	/* clear data and ensure it is not marked valid */
	memset(sk_info, 0, sizeof(struct sk_ts_info));
	return -1;
}

static int sk_interface_guidaddr(const char *name, unsigned char *guid)
{
	char file_name[64], buf[64], addr[8];
	FILE *f;
	char *err;
	int res;

	snprintf(file_name, sizeof buf, "/sys/class/net/%s/address", name);
	f = fopen(file_name, "r");
	if (!f) {
		pr_err("failed to open %s: %m", buf);
		return -1;
	}

	/* Set the file position to the beginning of the GUID */
	res = fseek(f, GUID_OFFSET, SEEK_SET);
	if (res) {
		pr_err("fseek failed: %m");
		goto error;
	}

	err = fgets(buf, sizeof buf, f);
	if (err == NULL) {
		pr_err("fseek failed: %m");
		goto error;
	}

	res = sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			   &addr[0], &addr[1], &addr[2], &addr[3],
			   &addr[4], &addr[5], &addr[6], &addr[7]);
	if (res != GUID_LEN) {
		pr_err("sscanf failed: %m");
		goto error;
	}

	memcpy(guid, addr, GUID_LEN);
	fclose(f);

	return 0;

error:
	fclose(f);
	return -1;
}

int sk_interface_macaddr(const char *name, struct address *mac)
{
	struct ifreq ifreq;
	int err, fd, type;

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("socket failed: %m");
		return -1;
	}

	err = ioctl(fd, SIOCGIFHWADDR, &ifreq);
	if (err < 0) {
		pr_err("ioctl SIOCGIFHWADDR failed: %m");
		close(fd);
		return -1;
	}

	close(fd);

	/* Get interface type */
	type = ifreq.ifr_hwaddr.sa_family;
	switch (type) {
		case ARPHRD_INFINIBAND:
			err = sk_interface_guidaddr(name, mac->sll.sll_addr);
			if (err) {
				pr_err("fail to get address using sysfs: %m");
				return -1;
			}
			mac->sll.sll_halen = EUI64;
			break;
		case ARPHRD_6LOWPAN:
			memcpy(mac->sll.sll_addr, &ifreq.ifr_hwaddr.sa_data,
			       GUID_LEN);
			mac->sll.sll_halen = EUI64;
			break;
		default:
			memcpy(mac->sll.sll_addr, &ifreq.ifr_hwaddr.sa_data, MAC_LEN);
			mac->sll.sll_halen = EUI48;
	}

	mac->sll.sll_family = AF_PACKET;
	mac->len = sizeof(mac->sll);
	return 0;
}

int sk_interface_addr(const char *name, int family, struct address *addr)
{
	struct ifaddrs *ifaddr, *i;
	int result = -1;

	if (getifaddrs(&ifaddr) == -1) {
		pr_err("getifaddrs failed: %m");
		return -1;
	}
	for (i = ifaddr; i; i = i->ifa_next) {
		if (i->ifa_addr && family == i->ifa_addr->sa_family &&
			strcmp(name, i->ifa_name) == 0)
		{
			switch (family) {
			case AF_INET:
				addr->len = sizeof(addr->sin);
				memcpy(&addr->sin, i->ifa_addr, addr->len);
				break;
			case AF_INET6:
				addr->len = sizeof(addr->sin6);
				memcpy(&addr->sin6, i->ifa_addr, addr->len);
				break;
			default:
				continue;
			}
			result = 0;
			break;
		}
	}
	freeifaddrs(ifaddr);
	return result;
}

static short sk_events = POLLPRI;
static short sk_revents = POLLPRI;

int sk_receive(int fd, void *buf, int buflen,
	       struct address *addr, struct hw_timestamp *hwts, int flags)
{
	char control[256];
	int cnt = 0, res = 0, level, type;
	struct cmsghdr *cm;
	struct iovec iov = { buf, buflen };
	struct msghdr msg;
	struct timespec *sw;
	struct timespec *ts = NULL;
	struct timehires *hr = NULL;

	memset(&hwts->ts, 0, sizeof(hwts->ts));
	memset(control, 0, sizeof(control));
	memset(&msg, 0, sizeof(msg));
	if (addr) {
		msg.msg_name = &addr->ss;
		msg.msg_namelen = sizeof(addr->ss);
	}
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if (flags == MSG_ERRQUEUE) {
		struct pollfd pfd = { fd, sk_events, 0 };
		res = poll(&pfd, 1, sk_tx_timeout);
		if (res < 1) {
			pr_err(res ? "poll for tx timestamp failed: %m" :
			             "timed out while polling for tx timestamp");
			pr_err("increasing tx_timestamp_timeout may correct "
			       "this issue, but it is likely caused by a driver bug");
			return res;
		} else if (!(pfd.revents & sk_revents)) {
			pr_err("poll for tx timestamp woke up on non ERR event");
			return -1;
		}
	}

	cnt = recvmsg(fd, &msg, flags);
	if (cnt < 1)
		pr_err("recvmsg%sfailed: %m",
		       flags == MSG_ERRQUEUE ? " tx timestamp " : " ");

	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		level = cm->cmsg_level;
		type  = cm->cmsg_type;
		if (SOL_SOCKET == level && SO_TIMESTAMPING == type) {
			if (cm->cmsg_len < 3 * sizeof(struct timespec)) {
				pr_warning("short SO_TIMESTAMPING message");
				return -1;
			}
			if (cm->cmsg_len >= 3 * sizeof(struct timespec) +
						sizeof(struct timehires)) {
				hr = (struct timehires *) (CMSG_DATA(cm) +
					3 * sizeof(struct timespec));
			}
			ts = (struct timespec *) CMSG_DATA(cm);
		}
		if (SOL_SOCKET == level && SO_TIMESTAMPNS == type) {
			if (cm->cmsg_len < sizeof(*sw)) {
				pr_warning("short SO_TIMESTAMPNS message");
				return -1;
			}
			sw = (struct timespec *) CMSG_DATA(cm);
			hwts->sw = timespec_to_tmv(*sw);
		}
	}

	if (addr)
		addr->len = msg.msg_namelen;

	switch (hwts->type) {
	case TS_SOFTWARE:
		if (ts)
			hwts->ts = timespec_to_tmv(ts[0]);
		break;
	case TS_HARDWARE:
	case TS_ONESTEP:
	case TS_P2P1STEP:
		if (hr && sk_high_res)
			hwts->ts = timehires_to_tmv(hr[0]);
		else if (ts)
			hwts->ts = timespec_to_tmv(ts[2]);
		break;
	case TS_LEGACY_HW:
		if (ts)
			hwts->ts = timespec_to_tmv(ts[1]);
		break;
	}
	return cnt;
}

int sk_set_priority(int fd, uint8_t dscp)
{
	int tos;
	socklen_t tos_len;

	tos_len = sizeof(tos);
	if (getsockopt(fd, SOL_IP, IP_TOS, &tos, &tos_len) < 0) {
		tos = 0;
	}

	/* clear old DSCP value */
	tos &= ~0xFC;

	/* set new DSCP value */
	tos |= dscp<<2;
	tos_len = sizeof(tos);
	if (setsockopt(fd, SOL_IP, IP_TOS, &tos, tos_len) < 0) {
		return -1;
	}

	return 0;
}

int sk_timestamping_init(int fd, const char *device, enum timestamp_type type,
			 enum transport_type transport)
{
	int err, filter1, filter2 = 0, flags, tx_type = HWTSTAMP_TX_ON;

	switch (type) {
	case TS_SOFTWARE:
		flags = SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
		break;
	case TS_HARDWARE:
	case TS_ONESTEP:
	case TS_P2P1STEP:
		flags = SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;
		if (sk_high_res)
			flags |= SOF_TIMESTAMPING_HIGH_RES;
		break;
	case TS_LEGACY_HW:
		flags = SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_SYS_HARDWARE;
		break;
	default:
		return -1;
	}

	if (type != TS_SOFTWARE) {
		filter1 = HWTSTAMP_FILTER_PTP_V2_EVENT;
		switch (type) {
		case TS_SOFTWARE:
			tx_type = HWTSTAMP_TX_OFF;
			break;
		case TS_HARDWARE:
		case TS_LEGACY_HW:
			tx_type = HWTSTAMP_TX_ON;
			break;
		case TS_ONESTEP:
			tx_type = HWTSTAMP_TX_ONESTEP_SYNC;
			break;
		case TS_P2P1STEP:
			tx_type = HWTSTAMP_TX_ONESTEP_P2P;
			break;
		}
		switch (transport) {
		case TRANS_UDP_IPV4:
		case TRANS_UDP_IPV6:
			filter2 = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;
			break;
		case TRANS_IEEE_802_3:
			filter2 = HWTSTAMP_FILTER_PTP_V2_L2_EVENT;
			break;
		case TRANS_DEVICENET:
		case TRANS_CONTROLNET:
		case TRANS_PROFINET:
		case TRANS_UDS:
			return -1;
		}
		err = hwts_init(fd, device, filter1, tx_type);
		if (err) {
			pr_info("driver rejected most general HWTSTAMP filter");
			err = hwts_init(fd, device, filter2, tx_type);
			if (err) {
				pr_err("ioctl SIOCSHWTSTAMP failed: %m");
				return err;
			}
		}
	}

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
		       &flags, sizeof(flags)) < 0) {
		pr_err("ioctl SO_TIMESTAMPING failed: %m");
		return -1;
	}

	flags = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE,
		       &flags, sizeof(flags)) < 0) {
		pr_warning("%s: SO_SELECT_ERR_QUEUE: %m", device);
		sk_events = 0;
		sk_revents = POLLERR;
	}

	/* Enable the sk_check_fupsync option, perhaps. */
	if (sk_general_init(fd)) {
		return -1;
	}

	return 0;
}
