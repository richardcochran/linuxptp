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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "print.h"
#include "sk.h"
#include "transport_private.h"
#include "udp.h"

#define EVENT_PORT        319
#define GENERAL_PORT      320
#define PTP_PRIMARY_MCAST_IPADDR "224.0.1.129"
#define PTP_PDELAY_MCAST_IPADDR  "224.0.0.107"

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

static int open_socket(char *name, struct in_addr mc_addr[2], short port)
{
	struct sockaddr_in addr;
	int fd, index, on = 1;

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

static int udp_open(struct transport *t, char *name, struct fdarray *fda,
		    enum timestamp_type ts_type)
{
	int efd, gfd;

	if (!inet_aton(PTP_PRIMARY_MCAST_IPADDR, &mcast_addr[MC_PRIMARY]))
		return -1;

	if (!inet_aton(PTP_PDELAY_MCAST_IPADDR, &mcast_addr[MC_PDELAY]))
		return -1;

	efd = open_socket(name, mcast_addr, EVENT_PORT);
	if (efd < 0)
		goto no_event;

	gfd = open_socket(name, mcast_addr, GENERAL_PORT);
	if (gfd < 0)
		goto no_general;

	if (sk_timestamping_init(efd, name, ts_type, TRANS_UDP_IPV4))
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
		    struct hw_timestamp *hwts)
{
	return sk_receive(fd, buf, buflen, hwts, 0);
}

static int udp_send(struct transport *t, struct fdarray *fda, int event, int peer,
		    void *buf, int len, struct hw_timestamp *hwts)
{
	ssize_t cnt;
	int fd = event ? fda->fd[FD_EVENT] : fda->fd[FD_GENERAL];
	struct sockaddr_in addr;
	unsigned char junk[1600];

	addr.sin_family = AF_INET;
	addr.sin_addr = peer ? mcast_addr[MC_PDELAY] : mcast_addr[MC_PRIMARY];
	addr.sin_port = htons(event ? EVENT_PORT : GENERAL_PORT);

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

static void udp_release(struct transport *t)
{
	/* No need for any per-instance deallocation. */
}

static struct transport the_udp_transport = {
	.close = udp_close,
	.open  = udp_open,
	.recv  = udp_recv,
	.send  = udp_send,
	.release = udp_release,
};

struct transport *udp_transport_create(void)
{
	/* No need for any per-instance allocation. */
	return &the_udp_transport;
}
