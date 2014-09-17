/**
 * @file hwstamp_ctl.c
 * @brief Utility program to set time stamping policy at the driver level.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>

#include "version.h"
#include "missing.h"

static void usage(char *progname)
{
	fprintf(stderr,
		"\n"
		"usage: %s [options]\n\n"
		" -h           prints this message and exits\n"
		" -i [device]  interface device to use, for example 'eth0'\n"
		" -r [%d..%d]   select receive time stamping:\n"
		"\t\t%2d time stamp no incoming packet at all\n"
		"\t\t%2d time stamp any incoming packet\n"
		"\t\t%2d (reserved value)\n"
		"\t\t%2d PTP v1, UDP, any kind of event packet\n"
		"\t\t%2d PTP v1, UDP, Sync packet\n"
		"\t\t%2d PTP v1, UDP, Delay_req packet\n"
		"\t\t%2d PTP v2, UDP, any kind of event packet\n"
		"\t\t%2d PTP v2, UDP, Sync packet\n"
		"\t\t%2d PTP v2, UDP, Delay_req packet\n"
		"\t\t%2d 802.AS1, Ethernet, any kind of event packet\n"
		"\t\t%2d 802.AS1, Ethernet, Sync packet\n"
		"\t\t%2d 802.AS1, Ethernet, Delay_req packet\n"
		"\t\t%2d PTP v2/802.AS1, any layer, any kind of event packet\n"
		"\t\t%2d PTP v2/802.AS1, any layer, Sync packet\n"
		"\t\t%2d PTP v2/802.AS1, any layer, Delay_req packet\n"
		" -t [%d|%d]     disable or enable transmit time stamping\n"
		" -v           prints the software version and exits\n"
		"\n",
		progname,
		HWTSTAMP_FILTER_NONE, HWTSTAMP_FILTER_PTP_V2_DELAY_REQ,
		HWTSTAMP_FILTER_NONE,
		HWTSTAMP_FILTER_ALL,
		HWTSTAMP_FILTER_SOME,
		HWTSTAMP_FILTER_PTP_V1_L4_EVENT,
		HWTSTAMP_FILTER_PTP_V1_L4_SYNC,
		HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ,
		HWTSTAMP_FILTER_PTP_V2_L4_EVENT,
		HWTSTAMP_FILTER_PTP_V2_L4_SYNC,
		HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ,
		HWTSTAMP_FILTER_PTP_V2_L2_EVENT,
		HWTSTAMP_FILTER_PTP_V2_L2_SYNC,
		HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ,
		HWTSTAMP_FILTER_PTP_V2_EVENT,
		HWTSTAMP_FILTER_PTP_V2_SYNC,
		HWTSTAMP_FILTER_PTP_V2_DELAY_REQ,
		HWTSTAMP_TX_OFF,
		HWTSTAMP_TX_ON);
}

int main(int argc, char *argv[])
{
	struct ifreq ifreq;
	struct hwtstamp_config cfg;
	char *device = NULL, *progname;
	int c, err, fd, rxopt = HWTSTAMP_FILTER_NONE, txopt = HWTSTAMP_TX_OFF;
	int setrx = 0, settx = 0;

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "hi:r:t:v"))) {
		switch (c) {
		case 'i':
			device = optarg;
			break;
		case 'r':
			setrx = 1;
			rxopt = atoi(optarg);
			break;
		case 't':
			settx = 1;
			txopt = atoi(optarg);
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'h':
			usage(progname);
			return 0;
		case '?':
		default:
			usage(progname);
			return -1;
		}
	}

	if (!device) {
		usage(progname);
		return -1;
	}

	if (rxopt < HWTSTAMP_FILTER_NONE ||
	    rxopt > HWTSTAMP_FILTER_PTP_V2_DELAY_REQ ||
	    txopt < HWTSTAMP_TX_OFF || txopt > HWTSTAMP_TX_ON) {
		usage(progname);
		return -1;
	}

	memset(&ifreq, 0, sizeof(ifreq));
	memset(&cfg, 0, sizeof(cfg));

	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

	ifreq.ifr_data = (void *) &cfg;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	/* First, attempt to get the current settings. */
	err = ioctl(fd, SIOCGHWTSTAMP, &ifreq);
	if (err < 0) {
		err = errno;
		if (err == ENOTTY)
			fprintf(stderr,
				"Kernel does not have support "
				"for non-destructive SIOCGHWTSTAMP.\n");
		else if (err == EOPNOTSUPP)
			fprintf(stderr,
				"Device driver does not have support "
				"for non-destructive SIOCGHWTSTAMP.\n");
		else
			perror("SIOCGHWTSTAMP failed");
	} else {
		printf("current settings:\n"
		       "tx_type %d\n"
		       "rx_filter %d\n",
		       cfg.tx_type, cfg.rx_filter);
	}

	/* Now, attempt to set values. Only change the values actually
	 * requested by user, rather than blindly resetting th zero if
	 * unrequested. */
	if (settx || setrx) {

		if (settx)
			cfg.tx_type = txopt;

		if (setrx)
			cfg.rx_filter = rxopt;

		err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
		if (err < 0) {
			err = errno;
			perror("SIOCSHWTSTAMP failed");
			if (err == ERANGE)
				fprintf(stderr,
					"The requested time stamping mode is "
					"not supported by the hardware.\n");
		} else {
			printf("new settings:\n"
			       "tx_type %d\n"
			       "rx_filter %d\n",
			       cfg.tx_type, cfg.rx_filter);
		}
	}

	return err;
}
