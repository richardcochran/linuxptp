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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "print.h"
#include "sk.h"
#include "transport_private.h"
#include "udp6.h"

#define EVENT_PORT        319
#define GENERAL_PORT      320
#define PTP_PRIMARY_MCAST_IP6ADDR "FF0E:0:0:0:0:0:0:181"
#define PTP_PDELAY_MCAST_IP6ADDR  "FF02:0:0:0:0:0:0:6B"

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

static int open_socket_ipv6(char *name, struct in6_addr mc_addr[2], short port)
{
	struct sockaddr_in6 addr;
	int fd, index, on = 1;

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

static int udp6_open(struct transport *t, char *name, struct fdarray *fda,
		    enum timestamp_type ts_type)
{
	int efd, gfd;

	if (1 != inet_pton(AF_INET6, PTP_PRIMARY_MCAST_IP6ADDR, &mc6_addr[MC_PRIMARY]))
		return -1;

	if (1 != inet_pton(AF_INET6, PTP_PDELAY_MCAST_IP6ADDR, &mc6_addr[MC_PDELAY]))
		return -1;

	efd = open_socket_ipv6(name, mc6_addr, EVENT_PORT);
	if (efd < 0)
		goto no_event;

	gfd = open_socket_ipv6(name, mc6_addr, GENERAL_PORT);
	if (gfd < 0)
		goto no_general;

	if (sk_timestamping_init(efd, name, ts_type, TRANS_UDP_IPV6))
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
		    struct hw_timestamp *hwts)
{
	return sk_receive(fd, buf, buflen, hwts, 0);
}

static int udp6_send(struct transport *t, struct fdarray *fda, int event, int peer,
		    void *buf, int len, struct hw_timestamp *hwts)
{
	ssize_t cnt;
	int fd = event ? fda->fd[FD_EVENT] : fda->fd[FD_GENERAL];
	struct sockaddr_in6 addr;
	unsigned char junk[1600];

	addr.sin6_family = AF_INET6;
	addr.sin6_addr = peer ? mc6_addr[MC_PDELAY] : mc6_addr[MC_PRIMARY];
	addr.sin6_port = htons(event ? EVENT_PORT : GENERAL_PORT);

	len += 2; /* Extend the payload by two, for UDP checksum corrections. */

	cnt = sendto(fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (cnt < 1) {
		pr_err("sendto failed: %m");
		return cnt;
	}
	/*
	 * Get the time stamp right away.
	 */
	return event ? sk_receive(fd, junk, len, hwts, MSG_ERRQUEUE) : cnt;
}

static void udp6_release(struct transport *t)
{
	/* No need for any per-instance deallocation. */
}

static struct transport the_udp6_transport = {
	.close = udp6_close,
	.open  = udp6_open,
	.recv  = udp6_recv,
	.send  = udp6_send,
	.release = udp6_release,
};

struct transport *udp6_transport_create(void)
{
	/* No need for any per-instance allocation. */
	return &the_udp6_transport;
}
