/**
 * @file raw.c
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
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include "address.h"
#include "config.h"
#include "contain.h"
#include "ether.h"
#include "missing.h"
#include "print.h"
#include "raw.h"
#include "sk.h"
#include "transport_private.h"
#include "util.h"

struct raw {
	struct transport t;
	struct address src_addr;
	struct address ptp_addr;
	struct address p2p_addr;
	int vlan;
};

#define PRP_TRAILER_LEN 6

/*
 * tcpdump -d \
 * '((ether[12:2] == 0x8100 and ether[12 + 4 :2] == 0x88F7 and ether[14+4 :1] & 0x8 == 0x8) or '\
 * ' (ether[12:2] == 0x88F7 and                                ether[14   :1] & 0x8 == 0x8)) and '\
 * 'not ether src de:ad:de:ad:be:ef'
 *
 * (000) ldh      [12]
 * (001) jeq      #0x8100          jt 2    jf 7
 * (002) ldh      [16]
 * (003) jeq      #0x88f7          jt 4    jf 16
 * (004) ldb      [18]
 * (005) and      #0x8
 * (006) jeq      #0x8             jt 11   jf 16
 * (007) jeq      #0x88f7          jt 8    jf 16
 * (008) ldb      [14]
 * (009) and      #0x8
 * (010) jeq      #0x8             jt 11   jf 16
 * (011) ld       [8]
 * (012) jeq      #0xdeadbeef      jt 13   jf 15
 * (013) ldh      [6]
 * (014) jeq      #0xdead          jt 16   jf 15
 * (015) ret      #262144
 * (016) ret      #0
 */
static struct sock_filter raw_filter_vlan_norm_general[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 5, 0x00008100 },
	{ 0x28, 0, 0, 0x00000010 },
	{ 0x15, 0, 12, 0x000088f7 },
	{ 0x30, 0, 0, 0x00000012 },
	{ 0x54, 0, 0, 0x00000008 },
	{ 0x15, 4, 9, 0x00000008 },
	{ 0x15, 0, 8, 0x000088f7 },
	{ 0x30, 0, 0, 0x0000000e },
	{ 0x54, 0, 0, 0x00000008 },
	{ 0x15, 0, 5, 0x00000008 },
	{ 0x20, 0, 0, 0x00000008 },
	{ 0x15, 0, 2, 0xdeadbeef },
	{ 0x28, 0, 0, 0x00000006 },
	{ 0x15, 1, 0, 0x0000dead },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

#define FILTER_EVENT_POS_SRC0 14
#define FILTER_EVENT_POS_SRC2 12

/*
 * tcpdump -d \
 *  '((ether[12:2] == 0x8100 and ether[12 + 4 :2] == 0x88F7 and ether[14+4 :1] & 0x8 != 0x8) or '\
 *  ' (ether[12:2] == 0x88F7 and                                ether[14   :1] & 0x8 != 0x8)) and '\
 *  'not ether src de:ad:de:ad:be:ef'
 *
 * (000) ldh      [12]
 * (001) jeq      #0x8100          jt 2    jf 7
 * (002) ldh      [16]
 * (003) jeq      #0x88f7          jt 4    jf 16
 * (004) ldb      [18]
 * (005) and      #0x8
 * (006) jeq      #0x8             jt 16   jf 11
 * (007) jeq      #0x88f7          jt 8    jf 16
 * (008) ldb      [14]
 * (009) and      #0x8
 * (010) jeq      #0x8             jt 16   jf 11
 * (011) ld       [8]
 * (012) jeq      #0xdeadbeef      jt 13   jf 15
 * (013) ldh      [6]
 * (014) jeq      #0xdead          jt 16   jf 15
 * (015) ret      #262144
 * (016) ret      #0
 */
static struct sock_filter raw_filter_vlan_norm_event[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 5, 0x00008100 },
	{ 0x28, 0, 0, 0x00000010 },
	{ 0x15, 0, 12, 0x000088f7 },
	{ 0x30, 0, 0, 0x00000012 },
	{ 0x54, 0, 0, 0x00000008 },
	{ 0x15, 9, 4, 0x00000008 },
	{ 0x15, 0, 8, 0x000088f7 },
	{ 0x30, 0, 0, 0x0000000e },
	{ 0x54, 0, 0, 0x00000008 },
	{ 0x15, 5, 0, 0x00000008 },
	{ 0x20, 0, 0, 0x00000008 },
	{ 0x15, 0, 2, 0xdeadbeef },
	{ 0x28, 0, 0, 0x00000006 },
	{ 0x15, 1, 0, 0x0000dead },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

#define FILTER_GENERAL_POS_SRC0 14
#define FILTER_GENERAL_POS_SRC2 12

static int raw_configure(int fd, int event, int index,
			 unsigned char *local_addr, unsigned char *addr1,
			 unsigned char *addr2, int enable)
{
	int err1, err2, option;
	struct packet_mreq mreq;
	struct sock_fprog prg;

	if (event) {
		prg.len = ARRAY_SIZE(raw_filter_vlan_norm_event);
		prg.filter = raw_filter_vlan_norm_event;

		memcpy(&prg.filter[FILTER_EVENT_POS_SRC0].k, local_addr, 2);
		memcpy(&prg.filter[FILTER_EVENT_POS_SRC2].k, local_addr + 2, 4);
		prg.filter[FILTER_EVENT_POS_SRC0].k =
			ntohs(prg.filter[FILTER_EVENT_POS_SRC0].k);
		prg.filter[FILTER_EVENT_POS_SRC2].k =
			ntohl(prg.filter[FILTER_EVENT_POS_SRC2].k);
	} else {
		prg.len = ARRAY_SIZE(raw_filter_vlan_norm_general);
		prg.filter = raw_filter_vlan_norm_general;

		memcpy(&prg.filter[FILTER_GENERAL_POS_SRC0].k, local_addr, 2);
		memcpy(&prg.filter[FILTER_GENERAL_POS_SRC2].k, local_addr + 2, 4);
		prg.filter[FILTER_GENERAL_POS_SRC0].k =
			ntohs(prg.filter[FILTER_GENERAL_POS_SRC0].k);
		prg.filter[FILTER_GENERAL_POS_SRC2].k =
			ntohl(prg.filter[FILTER_GENERAL_POS_SRC2].k);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prg, sizeof(prg))) {
		pr_err("setsockopt SO_ATTACH_FILTER failed: %m");
		return -1;
	}

	option = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = MAC_LEN;
	memcpy(mreq.mr_address, addr1, MAC_LEN);

	err1 = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (err1)
		pr_warning("setsockopt PACKET_MR_MULTICAST failed: %m");

	memcpy(mreq.mr_address, addr2, MAC_LEN);

	err2 = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (err2)
		pr_warning("setsockopt PACKET_MR_MULTICAST failed: %m");

	if (!err1 && !err2)
		return 0;

	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_ALLMULTI;
	mreq.mr_alen = 0;
	if (!setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq))) {
		return 0;
	}
	pr_warning("setsockopt PACKET_MR_ALLMULTI failed: %m");

	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 0;
	if (!setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq))) {
		return 0;
	}
	pr_warning("setsockopt PACKET_MR_PROMISC failed: %m");

	pr_err("all socket options failed");
	return -1;
}

static int raw_close(struct transport *t, struct fdarray *fda)
{
	close(fda->fd[0]);
	close(fda->fd[1]);
	return 0;
}

static int open_socket(const char *name, int event, unsigned char *local_addr,
		       unsigned char *ptp_dst_mac, unsigned char *p2p_dst_mac,
		       int socket_priority)
{
	struct sockaddr_ll addr;
	int fd, index;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		pr_err("socket failed: %m");
		goto no_socket;
	}
	index = sk_interface_index(fd, name);
	if (index < 0)
		goto no_option;

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = index;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("bind failed: %m");
		goto no_option;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		pr_err("setsockopt SO_BINDTODEVICE failed: %m");
		goto no_option;
	}

	if (socket_priority > 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &socket_priority,
		       sizeof(socket_priority))) {
		pr_err("setsockopt SO_PRIORITY failed: %m");
		goto no_option;
	}
	if (raw_configure(fd, event, index, local_addr, ptp_dst_mac,
			  p2p_dst_mac, 1))
		goto no_option;

	return fd;
no_option:
	close(fd);
no_socket:
	return -1;
}

static void mac_to_addr(struct address *addr, void *mac)
{
	addr->sll.sll_family = AF_PACKET;
	addr->sll.sll_halen = MAC_LEN;
	memcpy(addr->sll.sll_addr, mac, MAC_LEN);
	addr->len = sizeof(addr->sll);
}

static void addr_to_mac(void *mac, struct address *addr)
{
	memcpy(mac, &addr->sll.sll_addr, MAC_LEN);
}

/* Determines if the packet has Parallel Redundancy Protocol (PRP) trailer. */
static bool has_prp_trailer(unsigned char *ptr, int cnt)
{
	unsigned short suffix_id, lane_size_field, lsdu_size;
	int ptp_msg_len, trailer_start;
	struct ptp_header *hdr;

	/* try to parse like a PTP message to find out the message length */
	if (cnt < sizeof(struct ptp_header))
		return false;

	hdr = (struct ptp_header *)ptr;
	if ((hdr->ver & MAJOR_VERSION_MASK) != PTP_MAJOR_VERSION)
		return false;

	ptp_msg_len = ntohs(hdr->messageLength);

	if (cnt < (ptp_msg_len + PRP_TRAILER_LEN))
		return false;

	/* PRP trailer is always in the last six bytes before the FCS */
	trailer_start = cnt - PRP_TRAILER_LEN;

	/* PRP trailer (RCT) consists of 3 uint16.
	 | -------------------------------------------------------- |
	 | SeqNr(0-15) | LanId(0-3) LSDUsize(4-15) | Suffix (0-15)  |
	 | -------------------------------------------------------- |
	 - Sequence number is a running number and can't be verified
	 - LanId should be 0x1010 or 0x1011 (but should not be used for verification)
	 - LSDUsize should match LSDU length
	   (including possible padding and the RCT itself)
	 - Suffix should be 0x88FB
	*/

	/* Verify that the size in the RCT matches.
	   Size is the lower 12 bits
	*/
	lane_size_field = ntohs(*(unsigned short*)(ptr + trailer_start + 2));
	lsdu_size = lane_size_field & 0x0FFF;
	if (lsdu_size != cnt)
		return false;

	/* Verify the suffix */
	suffix_id = ntohs(*(unsigned short*)(ptr + trailer_start + 4));
	if (suffix_id == ETH_P_PRP)
	{
		return true;
	}

	return false;
}

static int raw_open(struct transport *t, struct interface *iface,
		    struct fdarray *fda, enum timestamp_type ts_type)
{
	struct raw *raw = container_of(t, struct raw, t);
	unsigned char ptp_dst_mac[MAC_LEN];
	unsigned char p2p_dst_mac[MAC_LEN];
	int efd, gfd, socket_priority;
	const char *name;
	char *str;

	name = interface_label(iface);
	str = config_get_string(t->cfg, name, "ptp_dst_mac");
	if (str2mac(str, ptp_dst_mac)) {
		pr_err("invalid ptp_dst_mac %s", str);
		return -1;
	}
	str = config_get_string(t->cfg, name, "p2p_dst_mac");
	if (str2mac(str, p2p_dst_mac)) {
		pr_err("invalid p2p_dst_mac %s", str);
		return -1;
	}
	mac_to_addr(&raw->ptp_addr, ptp_dst_mac);
	mac_to_addr(&raw->p2p_addr, p2p_dst_mac);

	if (sk_interface_macaddr(name, &raw->src_addr))
		goto no_mac;

	socket_priority = config_get_int(t->cfg, "global", "socket_priority");

	efd = open_socket(name, 1, raw->src_addr.sll.sll_addr, ptp_dst_mac,
			  p2p_dst_mac, socket_priority);
	if (efd < 0)
		goto no_event;

	gfd = open_socket(name, 0, raw->src_addr.sll.sll_addr, p2p_dst_mac,
			  p2p_dst_mac, socket_priority);
	if (gfd < 0)
		goto no_general;

	if (sk_timestamping_init(efd, name, ts_type, TRANS_IEEE_802_3,
				 interface_get_vclock(iface)))
		goto no_timestamping;

	if (sk_general_init(gfd))
		goto no_timestamping;

	fda->fd[FD_EVENT] = efd;
	fda->fd[FD_GENERAL] = gfd;
	return 0;

no_timestamping:
	close(gfd);
no_general:
	close(efd);
no_event:
no_mac:
	return -1;
}

static int raw_recv(struct transport *t, int fd, void *buf, int buflen,
		    struct address *addr, struct hw_timestamp *hwts)
{
	struct raw *raw = container_of(t, struct raw, t);
	unsigned char *ptr = buf;
	struct eth_hdr *hdr;
	int cnt, hlen;

	if (raw->vlan) {
		hlen = sizeof(struct vlan_hdr);
	} else {
		hlen = sizeof(struct eth_hdr);
	}
	ptr    -= hlen;
	buflen += hlen;
	hdr = (struct eth_hdr *) ptr;

	cnt = sk_receive(fd, ptr, buflen, addr, hwts, MSG_DONTWAIT);

	if (cnt >= 0)
		cnt -= hlen;
	if (cnt < 0)
		return cnt;

	if (has_prp_trailer(buf, cnt))
		cnt -= PRP_TRAILER_LEN;

	if (raw->vlan) {
		if (ETH_P_1588 == ntohs(hdr->type)) {
			pr_notice("raw: disabling VLAN mode");
			raw->vlan = 0;
		}
	} else {
		if (ETH_P_8021Q == ntohs(hdr->type)) {
			pr_notice("raw: switching to VLAN mode");
			raw->vlan = 1;
		}
	}
	return cnt;
}

static int raw_send(struct transport *t, struct fdarray *fda,
		    enum transport_event event, int peer, void *buf, int len,
		    struct address *addr, struct hw_timestamp *hwts)
{
	struct raw *raw = container_of(t, struct raw, t);
	ssize_t cnt;
	unsigned char pkt[1600], *ptr = buf;
	struct eth_hdr *hdr;
	int fd = -1;

	switch (event) {
	case TRANS_GENERAL:
		fd = fda->fd[FD_GENERAL];
		break;
	case TRANS_EVENT:
	case TRANS_ONESTEP:
	case TRANS_P2P1STEP:
	case TRANS_DEFER_EVENT:
		fd = fda->fd[FD_EVENT];
		break;
	}

	ptr -= sizeof(*hdr);
	len += sizeof(*hdr);

	if (!addr)
		addr = peer ? &raw->p2p_addr : &raw->ptp_addr;

	hdr = (struct eth_hdr *) ptr;
	addr_to_mac(&hdr->dst, addr);
	addr_to_mac(&hdr->src, &raw->src_addr);

	hdr->type = htons(ETH_P_1588);

	cnt = send(fd, ptr, len, 0);
	if (cnt < 1) {
		return -errno;
	}
	/*
	 * Get the time stamp right away.
	 */
	return event == TRANS_EVENT ? sk_receive(fd, pkt, len, NULL, hwts, MSG_ERRQUEUE) : cnt;
}

static void raw_release(struct transport *t)
{
	struct raw *raw = container_of(t, struct raw, t);
	free(raw);
}

static int raw_physical_addr(struct transport *t, uint8_t *addr)
{
	struct raw *raw = container_of(t, struct raw, t);
	addr_to_mac(addr, &raw->src_addr);
	return MAC_LEN;
}

static int raw_protocol_addr(struct transport *t, uint8_t *addr)
{
	struct raw *raw = container_of(t, struct raw, t);
	addr_to_mac(addr, &raw->src_addr);
	return MAC_LEN;
}

struct transport *raw_transport_create(void)
{
	struct raw *raw;
	raw = calloc(1, sizeof(*raw));
	if (!raw)
		return NULL;
	raw->t.close   = raw_close;
	raw->t.open    = raw_open;
	raw->t.recv    = raw_recv;
	raw->t.send    = raw_send;
	raw->t.release = raw_release;
	raw->t.physical_addr = raw_physical_addr;
	raw->t.protocol_addr = raw_protocol_addr;
	return &raw->t;
}
