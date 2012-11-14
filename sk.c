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

#include "print.h"
#include "sk.h"

/* globals */

int sk_tx_retries = 100;

/* private methods */

static int hwts_init(int fd, char *device, int rx_filter)
{
	struct ifreq ifreq;
	struct hwtstamp_config cfg, req;
	int err;

	memset(&ifreq, 0, sizeof(ifreq));
	memset(&cfg, 0, sizeof(cfg));

	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name));

	ifreq.ifr_data = (void *) &cfg;
	cfg.tx_type    = HWTSTAMP_TX_ON;
	cfg.rx_filter  = rx_filter;
	req = cfg;
	err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
	if (err < 0)
		return err;

	if (memcmp(&cfg, &req, sizeof(cfg))) {

		pr_warning("driver changed our HWTSTAMP options");
		pr_warning("tx_type   %d not %d", cfg.tx_type, req.tx_type);
		pr_warning("rx_filter %d not %d", cfg.rx_filter, req.rx_filter);

		if (cfg.tx_type != HWTSTAMP_TX_ON ||
		    (cfg.rx_filter != HWTSTAMP_FILTER_ALL &&
		     cfg.rx_filter != HWTSTAMP_FILTER_PTP_V2_EVENT)) {
			return -1;
		}
	}

	return 0;
}

/* public methods */

int sk_interface_index(int fd, char *name)
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

int sk_get_ts_info(char *name, struct sk_ts_info *sk_info)
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

	return 0;
failed:
#endif
	/* clear data and ensure it is not marked valid */
	memset(sk_info, 0, sizeof(struct sk_ts_info));
	return -1;
}

int sk_interface_macaddr(char *name, unsigned char *mac, int len)
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

int sk_receive(int fd, void *buf, int buflen,
	       struct hw_timestamp *hwts, int flags)
{
	char control[256];
	int cnt, level, try_again, type;
	struct cmsghdr *cm;
	struct iovec iov = { buf, buflen };
	struct msghdr msg;
	struct timespec *ts = NULL;

	memset(control, 0, sizeof(control));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	try_again = flags == MSG_ERRQUEUE ? sk_tx_retries : 1;

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
			break;
		}
	}

	if (cnt < 1) {
		if (flags == MSG_ERRQUEUE)
			pr_err("recvmsg tx timestamp failed: %m");
		else
			pr_err("recvmsg failed: %m");
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

int sk_timestamping_init(int fd, char *device, enum timestamp_type type,
			 enum transport_type transport)
{
	int err, filter1, filter2, flags;

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

	if (type != TS_SOFTWARE) {
		filter1 = HWTSTAMP_FILTER_PTP_V2_EVENT;
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
		err = hwts_init(fd, device, filter1);
		if (err) {
			pr_info("driver rejected most general HWTSTAMP filter");
			err = hwts_init(fd, device, filter2);
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

	return 0;
}
