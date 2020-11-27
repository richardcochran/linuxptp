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
#include <linux/genetlink.h>
#include <linux/if_team.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "missing.h"
#include "print.h"
#include "rtnl.h"

#define BUF_SIZE 4096
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))

static int rtnl_len;
static char *rtnl_buf;
static int get_team_active_iface(int master_index);

static int nl_close(int fd)
{
	return close(fd);
}

static int nl_open(int family)
{
	int fd;
	struct sockaddr_nl sa;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTNLGRP_LINK;

	fd = socket(AF_NETLINK, SOCK_RAW, family);
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

int rtnl_close(int fd)
{
	if (rtnl_buf) {
		free(rtnl_buf);
		rtnl_buf = NULL;
		rtnl_len = 0;
	}
	return nl_close(fd);
}

int rtnl_open(void)
{
	return nl_open(NETLINK_ROUTE);
}

static void rtnl_get_ts_device_callback(void *ctx, int linkup, int ts_index)
{
	int *dst = ctx;
	*dst = ts_index;
}

int rtnl_get_ts_device(const char *device, char ts_device[IF_NAMESIZE])
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

int rtnl_link_query(int fd, const char *device)
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

static inline __u8 rta_getattr_u8(struct rtattr *rta)
{
	return *(__u8 *)RTA_DATA(rta);
}

static inline __u16 rta_getattr_u16(struct rtattr *rta)
{
	return *(__u16 *)RTA_DATA(rta);
}

static inline __u32 rta_getattr_u32(struct rtattr *rta)
{
	return *(__u32 *)RTA_DATA(rta);
}

static inline char *rta_getattr_str(struct rtattr *rta)
{
	return (char *)RTA_DATA(rta);
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

static int rtnl_linkinfo_parse(int master_index, struct rtattr *rta)
{
	struct rtattr *linkinfo[IFLA_INFO_MAX];
	struct rtattr *bond[IFLA_BOND_MAX];
	int index = -1;
	char *kind;

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
		} else if (kind && !strncmp(kind, "team", 4)) {
			index = get_team_active_iface(master_index);
		}
	}
	return index;
}

int rtnl_link_status(int fd, const char *device, rtnl_callback cb, void *ctx)
{
	struct rtattr *tb[IFLA_MAX+1];
	struct ifinfomsg *info = NULL;
	int index, len, link_up;
	struct sockaddr_nl sa;
	int slave_index = -1;
	struct nlmsghdr *nh;
	struct msghdr msg;
	struct iovec iov;

	index = if_nametoindex(device);
	if (!rtnl_buf) {
		rtnl_len = BUF_SIZE;
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
			slave_index = rtnl_linkinfo_parse(index, tb[IFLA_LINKINFO]);

		if (cb)
			cb(ctx, link_up, slave_index);
	}

	return 0;
}

static int genl_send_msg(int fd, int family_id, int genl_cmd, int genl_version,
		  int rta_type, void *rta_data, int rta_len)
{
	struct sockaddr_nl daddr;
	struct genlmsghdr *gnlh;
	struct nlmsghdr *nlh;
	struct rtattr *attr;
	char msg[BUF_SIZE];

	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;

	memset(&msg, 0, sizeof(msg));
	nlh = (struct nlmsghdr *) msg;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	gnlh = (struct genlmsghdr *) NLMSG_DATA(nlh);
	gnlh->cmd = genl_cmd;
	gnlh->version = genl_version;

	if (rta_data && rta_len > 0) {
		attr = (struct rtattr *) GENLMSG_DATA(msg);
		attr->rta_type = rta_type;
		attr->rta_len = RTA_LENGTH(rta_len);
		nlh->nlmsg_len += NLMSG_ALIGN(attr->rta_len);
		if (nlh->nlmsg_len < sizeof(msg))
			memcpy(RTA_DATA(attr), rta_data, rta_len);
		else
			return -1;
	}

	return sendto(fd, &msg, nlh->nlmsg_len, 0,
		      (struct sockaddr *)&daddr, sizeof(daddr));
}

static int genl_get_family_id(int fd, void *family_name)
{
	struct rtattr *tb[CTRL_ATTR_MAX+1];
	struct nlmsghdr *nlh;
	struct rtattr *attr;
	char msg[BUF_SIZE];
	int len, gf_id;

	len = genl_send_msg(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
			    CTRL_ATTR_FAMILY_NAME, family_name,
			    strlen(family_name) + 1);
	if (len < 0)
		return len;

	len = recv(fd, &msg, sizeof(msg), 0);
	if (len < 0)
		return len;

	nlh = (struct nlmsghdr *) msg;
	if (nlh->nlmsg_type == NLMSG_ERROR || !NLMSG_OK(nlh, len))
		return -1;

	attr = (struct rtattr *) GENLMSG_DATA(msg);
	rtnl_rtattr_parse(tb, CTRL_ATTR_MAX, attr, NLMSG_PAYLOAD(nlh, GENL_HDRLEN));

	if (tb[CTRL_ATTR_FAMILY_ID])
		gf_id = rta_getattr_u16(tb[CTRL_ATTR_FAMILY_ID]);
	else
		gf_id = -1;

	return gf_id;
}

static int parse_team_list_option(struct rtattr *attr)
{
	struct rtattr *tb[TEAM_ATTR_OPTION_MAX+1];
	int len = RTA_PAYLOAD(attr);
	const char *optname = "";
	const char *mode = "";
	int active_index = -1;

	for (attr = RTA_DATA(attr); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
		rtnl_nested_rtattr_parse(tb, TEAM_ATTR_OPTION_MAX, attr);

		if (tb[TEAM_ATTR_OPTION_NAME])
			optname = rta_getattr_str(tb[TEAM_ATTR_OPTION_NAME]);

		if (!strcmp(optname, "mode") && tb[TEAM_ATTR_OPTION_TYPE] &&
		    rta_getattr_u8(tb[TEAM_ATTR_OPTION_TYPE]) == NLA_STRING)
			mode = rta_getattr_str(tb[TEAM_ATTR_OPTION_DATA]);

		if (!strcmp(optname, "activeport") && tb[TEAM_ATTR_OPTION_TYPE] &&
		    rta_getattr_u8(tb[TEAM_ATTR_OPTION_TYPE]) == NLA_U32)
			active_index = rta_getattr_u32(tb[TEAM_ATTR_OPTION_DATA]);
	}

	if (strcmp(mode, "activebackup")) {
		pr_err("team supported only in activebackup mode");
		return -1;
	} else {
		return active_index;
	}
}

static int get_team_active_iface(int master_index)
{
	struct rtattr *tb[TEAM_ATTR_MAX+1];
	struct genlmsghdr *gnlh;
	struct nlmsghdr *nlh;
	char msg[BUF_SIZE];
	int fd, gf_id, len;
	int index = -1;

	fd = nl_open(NETLINK_GENERIC);
	if (fd < 0)
		return fd;

	gf_id = genl_get_family_id(fd, TEAM_GENL_NAME);
	if (gf_id < 0) {
		pr_err("get genl family failed");
		goto no_info;
	}

	len = genl_send_msg(fd, gf_id, TEAM_CMD_OPTIONS_GET,
			    TEAM_GENL_VERSION, TEAM_ATTR_TEAM_IFINDEX,
			    &master_index, sizeof(master_index));
	if (len < 0) {
		pr_err("send team info request failed: %m");
		goto no_info;
	}

	len = recv(fd, msg, sizeof(msg), 0);
	if (len < 0) {
		pr_err("recv team info failed: %m");
		goto no_info;
	}

	nlh = (struct nlmsghdr *) msg;
	for ( ; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type != gf_id)
			continue;

		gnlh = (struct genlmsghdr *) NLMSG_DATA(nlh);
		if (gnlh->cmd != TEAM_CMD_OPTIONS_GET)
			continue;

		rtnl_rtattr_parse(tb, TEAM_ATTR_MAX, (struct rtattr *)GENLMSG_DATA(msg),
				  NLMSG_PAYLOAD(nlh, GENL_HDRLEN));

		if (tb[TEAM_ATTR_TEAM_IFINDEX] &&
		    master_index != rta_getattr_u32(tb[TEAM_ATTR_TEAM_IFINDEX]))
			continue;

		if (tb[TEAM_ATTR_LIST_OPTION]) {
			index = parse_team_list_option(tb[TEAM_ATTR_LIST_OPTION]);
			break;
		}
	}

no_info:
	nl_close(fd);
	return index;
}
