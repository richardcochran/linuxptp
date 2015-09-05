/**
 * @file udp.c
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
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
#include "udp.h"

#define EVENT_PORT        319
#define GENERAL_PORT      320
#define PTP_PRIMARY_MCAST_IPADDR "224.0.1.129"
#define PTP_PDELAY_MCAST_IPADDR  "224.0.0.107"

struct udp {
	struct transport t;
	struct address ip;
	struct address mac;
};

static int mcast_bind(int fd, int index)
{
	int err;
	struct ip_mreqn req;
	memset(&req, 0, sizeof(req));
	req.imr_ifindex = index;
	err = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &req, sizeof(req));
	if (err) {
		pr_err("setsockopt IP_MULTICAST_IF failed: %m");
		return -1;
	}
	return 0;
}

static int mcast_join(int fd, int index, const struct sockaddr *grp,
		      socklen_t grplen)
{
	int err, off = 0;
	struct ip_mreqn req;
	struct sockaddr_in *sa = (struct sockaddr_in *) grp;

	memset(&req, 0, sizeof(req));
	memcpy(&req.imr_multiaddr, &sa->sin_addr, sizeof(struct in_addr));
	req.imr_ifindex = index;
	err = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &req, sizeof(req));
	if (err) {
		pr_err("setsockopt IP_ADD_MEMBERSHIP failed: %m");
		return -1;
	}
	err = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
	if (err) {
		pr_err("setsockopt IP_MULTICAST_LOOP failed: %m");
		return -1;
	}
	return 0;
}

static int udp_close(struct transport *t, struct fdarray *fda)
{
	close(fda->fd[0]);
	close(fda->fd[1]);
	return 0;
}

static int open_socket(const char *name, struct in_addr mc_addr[2], short port,
		       int ttl)
{
	struct sockaddr_in addr;
	int fd, index, on = 1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("socket failed: %m");
		goto no_socket;
	}
	index = sk_interface_index(fd, name);
	if (index < 0)
		goto no_option;

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
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) {
		pr_err("setsockopt IP_MULTICAST_TTL failed: %m");
		goto no_option;
	}
	addr.sin_addr = mc_addr[0];
	if (mcast_join(fd, index, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("mcast_join failed");
		goto no_option;
	}
	addr.sin_addr = mc_addr[1];
	if (mcast_join(fd, index, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("mcast_join failed");
		goto no_option;
	}
	if (mcast_bind(fd, index)) {
		goto no_option;
	}
	return fd;
no_option:
	close(fd);
no_socket:
	return -1;
}

enum { MC_PRIMARY, MC_PDELAY };

static struct in_addr mcast_addr[2];

static int udp_open(struct transport *t, const char *name, struct fdarray *fda,
		    enum timestamp_type ts_type)
{
	struct udp *udp = container_of(t, struct udp, t);
	int efd, gfd, ttl;

	ttl = config_get_int(t->cfg, name, "udp_ttl");
	udp->mac.len = 0;
	sk_interface_macaddr(name, &udp->mac);

	udp->ip.len = 0;
	sk_interface_addr(name, AF_INET, &udp->ip);

	if (!inet_aton(PTP_PRIMARY_MCAST_IPADDR, &mcast_addr[MC_PRIMARY]))
		return -1;

	if (!inet_aton(PTP_PDELAY_MCAST_IPADDR, &mcast_addr[MC_PDELAY]))
		return -1;

	efd = open_socket(name, mcast_addr, EVENT_PORT, ttl);
	if (efd < 0)
		goto no_event;

	gfd = open_socket(name, mcast_addr, GENERAL_PORT, ttl);
	if (gfd < 0)
		goto no_general;

	if (sk_timestamping_init(efd, name, ts_type, TRANS_UDP_IPV4))
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

static int udp_recv(struct transport *t, int fd, void *buf, int buflen,
		    struct address *addr, struct hw_timestamp *hwts)
{
	return sk_receive(fd, buf, buflen, addr, hwts, 0);
}

static int udp_send(struct transport *t, struct fdarray *fda, int event,
		    int peer, void *buf, int len, struct address *addr,
		    struct hw_timestamp *hwts)
{
	ssize_t cnt;
	int fd = event ? fda->fd[FD_EVENT] : fda->fd[FD_GENERAL];
	struct address addr_buf;
	unsigned char junk[1600];

	if (!addr) {
		memset(&addr_buf, 0, sizeof(addr_buf));
		addr_buf.sin.sin_family = AF_INET;
		addr_buf.sin.sin_addr = peer ? mcast_addr[MC_PDELAY] :
					       mcast_addr[MC_PRIMARY];
		addr_buf.len = sizeof(addr_buf.sin);
		addr = &addr_buf;
	}

	addr->sin.sin_port = htons(event ? EVENT_PORT : GENERAL_PORT);

	/*
	 * Extend the payload by two, for UDP checksum correction.
	 * This is not really part of the standard, but it is the way
	 * that the phyter works.
	 */
	if (event == TRANS_ONESTEP)
		len += 2;

	cnt = sendto(fd, buf, len, 0, &addr->sa, sizeof(addr->sin));
	if (cnt < 1) {
		pr_err("sendto failed: %m");
		return cnt;
	}
	/*
	 * Get the time stamp right away.
	 */
	return event == TRANS_EVENT ? sk_receive(fd, junk, len, NULL, hwts, MSG_ERRQUEUE) : cnt;
}

static void udp_release(struct transport *t)
{
	struct udp *udp = container_of(t, struct udp, t);
	free(udp);
}

static int udp_physical_addr(struct transport *t, uint8_t *addr)
{
	struct udp *udp = container_of(t, struct udp, t);
	int len = 0;

	if (udp->mac.len) {
		len = MAC_LEN;
		memcpy(addr, udp->mac.sll.sll_addr, len);
	}
	return len;
}

static int udp_protocol_addr(struct transport *t, uint8_t *addr)
{
	struct udp *udp = container_of(t, struct udp, t);
	int len = 0;

	if (udp->ip.len) {
		len = sizeof(udp->ip.sin.sin_addr.s_addr);
		memcpy(addr, &udp->ip.sin.sin_addr.s_addr, len);
	}
	return len;
}

struct transport *udp_transport_create(void)
{
	struct udp *udp = calloc(1, sizeof(*udp));
	if (!udp)
		return NULL;
	udp->t.close = udp_close;
	udp->t.open  = udp_open;
	udp->t.recv  = udp_recv;
	udp->t.send  = udp_send;
	udp->t.release = udp_release;
	udp->t.physical_addr = udp_physical_addr;
	udp->t.protocol_addr = udp_protocol_addr;
	return &udp->t;
}
