/**
 * @file udp6.c
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "address.h"
#include "config.h"
#include "contain.h"
#include "print.h"
#include "sk.h"
#include "ether.h"
#include "transport_private.h"
#include "udp6.h"

#define EVENT_PORT        319
#define GENERAL_PORT      320
#define PTP_PRIMARY_MCAST_IP6ADDR "FF0E:0:0:0:0:0:0:181"
#define PTP_PDELAY_MCAST_IP6ADDR  "FF02:0:0:0:0:0:0:6B"

struct udp6 {
	struct transport t;
	int index;
	struct address ip;
	struct address mac;
};

static int is_link_local(struct in6_addr *addr)
{
	return addr->s6_addr[1] == 0x02 ? 1 : 0;
}

static int mc_bind(int fd, int index)
{
	int err;
	struct ipv6_mreq req;
	memset(&req, 0, sizeof(req));
	req.ipv6mr_interface = index;
	err = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &req, sizeof(req));
	if (err) {
		pr_err("setsockopt IPV6_MULTICAST_IF failed: %m");
		return -1;
	}
	return 0;
}

static int mc_join(int fd, int index, const struct sockaddr *grp, socklen_t grplen)
{
	int err, off = 0;
	struct ipv6_mreq req;
	struct sockaddr_in6 *sa = (struct sockaddr_in6 *) grp;

	memset(&req, 0, sizeof(req));
	memcpy(&req.ipv6mr_multiaddr, &sa->sin6_addr, sizeof(struct in6_addr));
	req.ipv6mr_interface = index;
	err = setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &req, sizeof(req));
	if (err) {
		pr_err("setsockopt IPV6_ADD_MEMBERSHIP failed: %m");
		return -1;
	}
	err = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &off, sizeof(off));
	if (err) {
		pr_err("setsockopt IPV6_MULTICAST_LOOP failed: %m");
		return -1;
	}
	return 0;
}

static int udp6_close(struct transport *t, struct fdarray *fda)
{
	close(fda->fd[0]);
	close(fda->fd[1]);
	return 0;
}

static int open_socket_ipv6(const char *name, struct in6_addr mc_addr[2], short port,
			    int *interface_index, int hop_limit)
{
	struct sockaddr_in6 addr;
	int fd, index, on = 1;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(port);

	fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("socket failed: %m");
		goto no_socket;
	}
	index = sk_interface_index(fd, name);
	if (index < 0)
		goto no_option;

	*interface_index = index;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		pr_err("setsockopt SO_REUSEADDR failed: %m");
		goto no_option;
	}
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("bind failed: %m");
		goto no_option;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		pr_err("setsockopt SO_BINDTODEVICE failed: %m");
		goto no_option;
	}
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hop_limit,
		       sizeof(hop_limit))) {
		pr_err("setsockopt IPV6_MULTICAST_HOPS failed: %m");
		goto no_option;
	}
	addr.sin6_addr = mc_addr[0];
	if (mc_join(fd, index, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("mcast_join failed");
		goto no_option;
	}
	addr.sin6_addr = mc_addr[1];
	if (mc_join(fd, index, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("mcast_join failed");
		goto no_option;
	}
	if (mc_bind(fd, index)) {
		goto no_option;
	}
	return fd;
no_option:
	close(fd);
no_socket:
	return -1;
}

enum { MC_PRIMARY, MC_PDELAY };

static struct in6_addr mc6_addr[2];

static int udp6_open(struct transport *t, const char *name, struct fdarray *fda,
		    enum timestamp_type ts_type)
{
	struct udp6 *udp6 = container_of(t, struct udp6, t);
	int efd, gfd, hop_limit;

	hop_limit = config_get_int(t->cfg, name, "udp_ttl");
	udp6->mac.len = 0;
	sk_interface_macaddr(name, &udp6->mac);

	udp6->ip.len = 0;
	sk_interface_addr(name, AF_INET6, &udp6->ip);

	if (1 != inet_pton(AF_INET6, PTP_PRIMARY_MCAST_IP6ADDR, &mc6_addr[MC_PRIMARY]))
		return -1;

	mc6_addr[MC_PRIMARY].s6_addr[1] = config_get_int(t->cfg, name, "udp6_scope");

	if (1 != inet_pton(AF_INET6, PTP_PDELAY_MCAST_IP6ADDR, &mc6_addr[MC_PDELAY]))
		return -1;

	efd = open_socket_ipv6(name, mc6_addr, EVENT_PORT, &udp6->index, hop_limit);
	if (efd < 0)
		goto no_event;

	gfd = open_socket_ipv6(name, mc6_addr, GENERAL_PORT, &udp6->index, hop_limit);
	if (gfd < 0)
		goto no_general;

	if (sk_timestamping_init(efd, name, ts_type, TRANS_UDP_IPV6))
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
	return -1;
}

static int udp6_recv(struct transport *t, int fd, void *buf, int buflen,
		     struct address *addr, struct hw_timestamp *hwts)
{
	return sk_receive(fd, buf, buflen, addr, hwts, 0);
}

static int udp6_send(struct transport *t, struct fdarray *fda, int event,
		    int peer, void *buf, int len, struct address *addr,
		    struct hw_timestamp *hwts)
{
	struct udp6 *udp6 = container_of(t, struct udp6, t);
	ssize_t cnt;
	int fd = event ? fda->fd[FD_EVENT] : fda->fd[FD_GENERAL];
	struct address addr_buf;
	unsigned char junk[1600];

	if (!addr) {
		memset(&addr_buf, 0, sizeof(addr_buf));
		addr_buf.sin6.sin6_family = AF_INET6;
		addr_buf.sin6.sin6_addr =  peer ? mc6_addr[MC_PDELAY] :
						  mc6_addr[MC_PRIMARY];
		if (is_link_local(&addr_buf.sin6.sin6_addr))
			addr_buf.sin6.sin6_scope_id = udp6->index;

		addr_buf.len = sizeof(addr_buf.sin6);
		addr = &addr_buf;
	}

	addr->sin6.sin6_port = htons(event ? EVENT_PORT : GENERAL_PORT);

	len += 2; /* Extend the payload by two, for UDP checksum corrections. */

	cnt = sendto(fd, buf, len, 0, &addr->sa, sizeof(addr->sin6));
	if (cnt < 1) {
		pr_err("sendto failed: %m");
		return cnt;
	}
	/*
	 * Get the time stamp right away.
	 */
	return event == TRANS_EVENT ? sk_receive(fd, junk, len, NULL, hwts, MSG_ERRQUEUE) : cnt;
}

static void udp6_release(struct transport *t)
{
	struct udp6 *udp6 = container_of(t, struct udp6, t);
	free(udp6);
}

static int udp6_physical_addr(struct transport *t, uint8_t *addr)
{
	struct udp6 *udp6 = container_of(t, struct udp6, t);
	int len = 0;

	if (udp6->mac.len) {
		len = MAC_LEN;
		memcpy(addr, udp6->mac.sll.sll_addr, len);
	}
	return len;
}

static int udp6_protocol_addr(struct transport *t, uint8_t *addr)
{
	struct udp6 *udp6 = container_of(t, struct udp6, t);
	int len = 0;

	if (udp6->ip.len) {
		len = sizeof(udp6->ip.sin6.sin6_addr.s6_addr);
		memcpy(addr, &udp6->ip.sin6.sin6_addr.s6_addr, len);
	}
	return len;
}

struct transport *udp6_transport_create(void)
{
	struct udp6 *udp6;
	udp6 = calloc(1, sizeof(*udp6));
	if (!udp6)
		return NULL;
	udp6->t.close   = udp6_close;
	udp6->t.open    = udp6_open;
	udp6->t.recv    = udp6_recv;
	udp6->t.send    = udp6_send;
	udp6->t.release = udp6_release;
	udp6->t.physical_addr = udp6_physical_addr;
	udp6->t.protocol_addr = udp6_protocol_addr;
	return &udp6->t;
}
