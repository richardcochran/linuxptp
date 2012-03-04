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

#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include "print.h"
#include "udp.h"

#define EVENT_PORT        319
#define GENERAL_PORT      320
#define MULTICAST_IP_ADDR "224.0.1.129"

static int hwts_init(int fd, char *device)
{
	struct ifreq ifreq;
	struct hwtstamp_config cfg, req;
	int err;

	memset(&ifreq, 0, sizeof(ifreq));
	memset(&cfg, 0, sizeof(cfg));

	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name));

	ifreq.ifr_data = (void *) &cfg;
	cfg.tx_type    = HWTSTAMP_TX_ON;
	cfg.rx_filter  = HWTSTAMP_FILTER_PTP_V2_EVENT;

	req = cfg;
	err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
	if (err < 0)
		pr_err("ioctl SIOCSHWTSTAMP failed: %m");

	if (memcmp(&cfg, &req, sizeof(cfg))) {

		pr_warning("driver changed our HWTSTAMP options");
		pr_warning("tx_type   %d not %d", cfg.tx_type, req.tx_type);
		pr_warning("rx_filter %d not %d", cfg.rx_filter, req.rx_filter);

		if (cfg.tx_type != HWTSTAMP_TX_ON ||
		    cfg.rx_filter != HWTSTAMP_FILTER_ALL) {
			return -1;
		}
	}

	return err ? errno : 0;
}

static int timestamping_init(int fd, char *device, enum timestamp_type type)
{
	int flags;

	switch (type) {
	case TS_SOFTWARE:
		flags = SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
		break;
	case TS_HARDWARE:
		flags = SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;
		break;
	case TS_LEGACY_HW:
		flags = SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_SYS_HARDWARE;
		break;
	default:
		return -1;
	}

	if (type != TS_SOFTWARE && hwts_init(fd, device))
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
		       &flags, sizeof(flags)) < 0) {
		pr_err("ioctl SO_TIMESTAMPING failed: %m");
		return -1;
	}

	return 0;
}

static int interface_index(int fd, char *name)
{
	struct ifreq ifreq;
	int err;

	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, name);
	err = ioctl(fd, SIOCGIFINDEX, &ifreq);
	if (err < 0) {
		pr_err("ioctl SIOCGIFINDEX failed: %m");
		return err;
	}
	return ifreq.ifr_ifindex;
}

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

int udp_close(struct fdarray *fda)
{
	close(fda->fd[0]);
	close(fda->fd[1]);
	return 0;
}

static int open_socket(char *name, struct in_addr *mc_addr, short port)
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
	index = interface_index(fd, name);
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
	addr.sin_addr = *mc_addr;
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

static struct in_addr mc_addr;

int udp_open(char *name, struct fdarray *fda, enum timestamp_type ts_type)
{
	int efd, gfd;

	if (!inet_aton(MULTICAST_IP_ADDR, &mc_addr))
		return -1;

	efd = open_socket(name, &mc_addr, EVENT_PORT);
	if (efd < 0)
		goto no_event;

	gfd = open_socket(name, &mc_addr, GENERAL_PORT);
	if (gfd < 0)
		goto no_general;

	if (timestamping_init(efd, name, ts_type))
		goto no_timestamping;

	fda->fd[FD_EVENT] = efd;
	fda->fd[FD_GENERAL] = gfd;
	fda->cnt = 2;
	return 0;

no_timestamping:
	close(gfd);
no_general:
	close(efd);
no_event:
	return -1;
}

static int receive(int fd, void *buf, int buflen,
		   struct hw_timestamp *hwts, int flags)
{
	char control[256];
	int cnt, level, try_again, type;
	struct cmsghdr *cm;
	struct iovec iov = { buf, buflen };
	struct msghdr msg;
	struct timespec *ts = NULL;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	try_again = flags == MSG_ERRQUEUE ? 2 : 1;

	for ( ; try_again; try_again--) {
		cnt = recvmsg(fd, &msg, flags);
		if (cnt >= 0) {
			break;
		}
		if (errno == EINTR) {
			try_again++;
		} else if (errno == EAGAIN) {
			usleep(1);
		} else {
			if (flags == MSG_ERRQUEUE)
				pr_err("recvmsg tx timestamp failed: %m");
			else
				pr_err("recvmsg failed: %m");
			break;
		}
	}

	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		level = cm->cmsg_level;
		type  = cm->cmsg_type;
		if (SOL_SOCKET == level && SO_TIMESTAMPING == type) {
			if (cm->cmsg_len < sizeof(*ts) * 3) {
				pr_warning("short SO_TIMESTAMPING message");
				return -1;
			}
			ts = (struct timespec *) CMSG_DATA(cm);
			break;
		}
	}

	if (!ts) {
		memset(&hwts->ts, 0, sizeof(hwts->ts));
		return cnt;
	}

	switch (hwts->type) {
	case TS_SOFTWARE:
		hwts->ts = ts[0];
		break;
	case TS_HARDWARE:
		hwts->ts = ts[2];
		break;
	case TS_LEGACY_HW:
		hwts->ts = ts[1];
		break;
	}
	return cnt;
}

int udp_recv(int fd, void *buf, int buflen, struct hw_timestamp *hwts)
{
	return receive(fd, buf, buflen, hwts, 0);
}

int udp_send(struct fdarray *fda, int event,
	     void *buf, int len, struct hw_timestamp *hwts)
{
	ssize_t cnt;
	int fd = event ? fda->fd[FD_EVENT] : fda->fd[FD_GENERAL];
	struct sockaddr_in addr;
	unsigned char junk[1600];

	addr.sin_family = AF_INET;
	addr.sin_addr = mc_addr;
	addr.sin_port = htons(event ? EVENT_PORT : GENERAL_PORT);

	cnt = sendto(fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (cnt < 1) {
		pr_err("sendto failed: %m");
		return cnt;
	}
	/*
	 * Get the time stamp right away.
	 */
	return event ? receive(fd, junk, len, hwts, MSG_ERRQUEUE) : cnt;
}

int udp_interface_macaddr(char *name, unsigned char *mac, int len)
{
	struct ifreq ifreq;
	int err, fd;

	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, name);

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

	memcpy(mac, ifreq.ifr_hwaddr.sa_data, len);
	close(fd);
	return 0;
}
