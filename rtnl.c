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
#include <sys/socket.h> /* Must come before linux/netlink.h on some systems. */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "missing.h"
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

static void rtnl_get_ts_device_callback(void *ctx, int linkup, int ts_index)
{
	int *dst = ctx;
	*dst = ts_index;
}

int rtnl_get_ts_device(char *device, char *ts_device)
{
	int err, fd;
	int ts_index = -1;

	fd = rtnl_open();
	if (fd < 0)
		return fd;

	err = rtnl_link_query(fd, device);
	if (err) {
		goto no_info;
	}

	rtnl_link_status(fd, device, rtnl_get_ts_device_callback, &ts_index);
	if (ts_index > 0 && if_indextoname(ts_index, ts_device))
		err = 0;
	else
		err = -1;

no_info:
	rtnl_close(fd);
	return err;
}

int rtnl_link_query(int fd, char *device)
{
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct iovec iov;
	int cnt;

	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifm;
	} __attribute__((packed)) request;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	memset(&request, 0, sizeof(request));
	request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.ifm));
	request.hdr.nlmsg_type = RTM_GETLINK;
	request.hdr.nlmsg_flags = NLM_F_REQUEST;
	request.hdr.nlmsg_seq = 1;
	request.hdr.nlmsg_pid = 0;
	request.ifm.ifi_family = AF_UNSPEC;
	request.ifm.ifi_index = if_nametoindex(device ? device : "");
	request.ifm.ifi_change = 0xffffffff;

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

static inline __u32 rta_getattr_u32(const struct rtattr *rta)
{
	return *(__u32 *)RTA_DATA(rta);
}

static inline const char *rta_getattr_str(const struct rtattr *rta)
{
	return (const char *)RTA_DATA(rta);
}

static int rtnl_rtattr_parse(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * max);
	while (RTA_OK(rta, len)) {
		type = rta->rta_type;
		if ((type < max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len) {
		pr_err("Length mismatch: len %d, rta_len=%d\n", len, rta->rta_len);
		return -1;
	}

	return 0;
}

static inline int rtnl_nested_rtattr_parse(struct rtattr *tb[], int max, struct rtattr *rta)
{
	return rtnl_rtattr_parse(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

static int rtnl_linkinfo_parse(struct rtattr *rta)
{
	int index = -1;
	const char *kind;
	struct rtattr *linkinfo[IFLA_INFO_MAX];
	struct rtattr *bond[IFLA_BOND_MAX];

	if (rtnl_nested_rtattr_parse(linkinfo, IFLA_INFO_MAX, rta) < 0)
		return -1;

	if (linkinfo[IFLA_INFO_KIND]) {
		kind = rta_getattr_str(linkinfo[IFLA_INFO_KIND]);

		if (kind && !strncmp(kind, "bond", 4) &&
		    linkinfo[IFLA_INFO_DATA]) {
			if (rtnl_nested_rtattr_parse(bond, IFLA_BOND_MAX,
						 linkinfo[IFLA_INFO_DATA]) < 0)
				return -1;

			if (bond[IFLA_BOND_ACTIVE_SLAVE]) {
				index = rta_getattr_u32(bond[IFLA_BOND_ACTIVE_SLAVE]);
			}
		}
	}
	return index;
}

int rtnl_link_status(int fd, char *device, rtnl_callback cb, void *ctx)
{
	int index, len, link_up;
	int slave_index = -1;
	struct iovec iov;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;
	struct ifinfomsg *info = NULL;
	struct rtattr *tb[IFLA_MAX+1];

	index = if_nametoindex(device);
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
		if (nh->nlmsg_type != RTM_NEWLINK)
			continue;

		info = NLMSG_DATA(nh);
		if (index != info->ifi_index)
			continue;

		link_up = info->ifi_flags & IFF_RUNNING ? 1 : 0;
		pr_debug("interface index %d is %s", index,
			 link_up ? "up" : "down");

		rtnl_rtattr_parse(tb, IFLA_MAX, IFLA_RTA(info),
				  IFLA_PAYLOAD(nh));

		if (tb[IFLA_LINKINFO])
			slave_index = rtnl_linkinfo_parse(tb[IFLA_LINKINFO]);

		if (cb)
			cb(ctx, link_up, slave_index);
	}

	return 0;
}

int rtnl_open(void)
{
	int fd;
	struct sockaddr_nl sa;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTNLGRP_LINK;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		pr_err("failed to open netlink socket: %m");
		return -1;
	}
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa))) {
		pr_err("failed to bind netlink socket: %m");
		close(fd);
		return -1;
	}
	return fd;
}
