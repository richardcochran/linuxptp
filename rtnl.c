/**
 * @file rtnl.c
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
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "print.h"
#include "rtnl.h"

static int rtnl_len;
static char *rtnl_buf;

int rtnl_close(int fd)
{
	if (rtnl_buf) {
		free(rtnl_buf);
		rtnl_buf = NULL;
		rtnl_len = 0;
	}
	return close(fd);
}

int rtnl_link_query(int fd)
{
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct iovec iov;
	int cnt;

	struct {
		struct nlmsghdr hdr;
		struct rtgenmsg gen;
	} __attribute__((packed)) request;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	memset(&request, 0, sizeof(request));
	request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.gen));
	request.hdr.nlmsg_type = RTM_GETLINK;
	request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.hdr.nlmsg_seq = 1;
	request.hdr.nlmsg_pid = 0;
	request.gen.rtgen_family = AF_UNSPEC;

	iov.iov_base = &request;
	iov.iov_len = sizeof(request);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	cnt = sendmsg(fd, &msg, 0);
	if (cnt < 0) {
		pr_err("rtnl: sendmsg: %m");
		return -1;
	}
	return 0;
}

int rtnl_link_status(int fd, rtnl_callback cb, void *ctx)
{
	int index, len;
	struct iovec iov;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct ifinfomsg *info = NULL;

	if (!rtnl_buf) {
		rtnl_len = 4096;
		rtnl_buf = malloc(rtnl_len);
		if (!rtnl_buf) {
			pr_err("rtnl: low memory");
			return -1;
		}
	}

	iov.iov_base = rtnl_buf;
	iov.iov_len = rtnl_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC);
	if (len < 1) {
		pr_err("rtnl: recvmsg: %m");
		return -1;
	}
	if (len > rtnl_len) {
		free(rtnl_buf);
		rtnl_len = len;
		rtnl_buf = malloc(len);
		if (!rtnl_buf) {
			pr_err("rtnl: failed to resize to %d bytes", len);
			return -1;
		}
		iov.iov_base = rtnl_buf;
		iov.iov_len = rtnl_len;
	}

	len = recvmsg(fd, &msg, 0);
	if (len < 1) {
		pr_err("rtnl: recvmsg: %m");
		return -1;
	}
	nh = (struct nlmsghdr *) rtnl_buf;

	for ( ; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_type == RTM_NEWLINK) {
			info = NLMSG_DATA(nh);
			index = info->ifi_index;
			pr_debug("interface index %d is %s", index,
				 info->ifi_flags & IFF_RUNNING ? "up" : "down");
			cb(ctx, index, info->ifi_flags & IFF_RUNNING ? 1 : 0);
		}
	}
	return 0;
}

int rtnl_open(void)
{
	int fd;
	struct sockaddr_nl sa;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		pr_err("failed to open netlink socket: %m");
		return -1;
	}
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa))) {
		pr_err("failed to bind netlink socket: %m");
		return -1;
	}
	return fd;
}
