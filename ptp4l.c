/**
 * @file ptp4l.c
 * @brief PTP Boundary Clock main program
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clock.h"
#include "config.h"
#include "print.h"
#include "sk.h"
#include "transport.h"
#include "util.h"

int assume_two_step;
double configured_pi_kp, configured_pi_ki; /*see pi.c*/
extern unsigned char ptp_dst_mac[]; /*see raw.c*/
extern unsigned char p2p_dst_mac[]; /*see raw.c*/

static int running = 1;
static struct defaultDS ds;
static struct port_defaults pod;
static struct config cfg_settings;

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" Delay Mechanism (per interface)\n\n"
		" -A        Auto, starting with E2E\n"
		" -E        E2E, delay request-response (default)\n"
		" -P        P2P, peer delay mechanism\n\n"
		" Network Transport (per interface)\n\n"
		" -2        IEEE 802.3\n"
		" -4        UDP IPV4 (default)\n"
		" -6        UDP IPV6\n\n"
		" Time Stamping\n\n"
		" -H        HARDWARE (default)\n"
		" -S        SOFTWARE\n"
		" -L        LEGACY HW\n\n"
		" Other Options\n\n"
		" -f [file] read configuration from 'file'\n"
		" -i [dev]  interface device to use, for example 'eth0'\n"
		"           (may be specified multiple times)\n"
		" -p [dev]  PTP hardware clock device to use, default auto\n"
		"           (ignored for SOFTWARE/LEGACY HW time stamping)\n"
		" -s        slave only mode (overrides configuration file)\n"
		" -l [num]  set the logging level to 'num'\n"
		" -q        do not print messages to the syslog\n"
		" -v        print messages to stdout\n"
		" -h        prints this message and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *config = NULL, *req_phc = NULL, *progname;
	int c, slaveonly = 0;
	struct interface *iface = cfg_settings.iface;
	int *nports = &cfg_settings.nports;
	enum delay_mechanism dm = DM_E2E;
	enum transport_type transport = TRANS_UDP_IPV4;
	enum timestamp_type timestamping = TS_HARDWARE;
	struct clock *clock;
	int phc_index = -1;

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "AEP246HSLf:i:p:sl:qvh"))) {
		switch (c) {
		case 'A':
			dm = DM_AUTO;
			break;
		case 'E':
			dm = DM_E2E;
			break;
		case 'P':
			dm = DM_P2P;
			break;
		case '2':
			transport = TRANS_IEEE_802_3;
			break;
		case '4':
			transport = TRANS_UDP_IPV4;
			break;
		case '6':
			transport = TRANS_UDP_IPV6;
			break;
		case 'H':
			timestamping = TS_HARDWARE;
			break;
		case 'S':
			timestamping = TS_SOFTWARE;
			break;
		case 'L':
			timestamping = TS_LEGACY_HW;
			break;
		case 'f':
			config = optarg;
			break;
		case 'i':
			if (*nports < MAX_PORTS) {
				iface[*nports].name = optarg;
				iface[*nports].dm = dm;
				iface[*nports].transport = transport;
				(*nports)++;
			} else {
				fprintf(stderr, "too many interfaces\n");
				return -1;
			}
			break;
		case 'p':
			req_phc = optarg;
			break;
		case 's':
			slaveonly = 1;
			break;
		case 'l':
			print_set_level(atoi(optarg));
			break;
		case 'q':
			print_set_syslog(1);
			break;
		case 'v':
			print_set_verbose(1);
			break;
		case 'h':
			usage(progname);
			return 0;
		case '?':
			usage(progname);
			return -1;
		default:
			usage(progname);
			return -1;
		}
	}

	if (!*nports) {
		fprintf(stderr, "no interface specified\n");
		usage(progname);
		return -1;
	}

	/* determine PHC Clock index */
	if (timestamping == TS_SOFTWARE || timestamping == TS_LEGACY_HW) {
		phc_index = -1;
	} else if (req_phc) {
		if (1 != sscanf(req_phc, "/dev/ptp%d", &phc_index)) {
			fprintf(stderr, "bad ptp device string\n");
			return -1;
		}
	} else if (sk_interface_phc(iface[0].name, &phc_index)) {
		fprintf(stderr, "get_ts_info not supported\n"
				"please specify ptp device\n");
		return -1;
	}

	if (phc_index >= 0) {
		pr_info("selected /dev/ptp%d as PTP clock", phc_index);
	}

	ds.slaveOnly = FALSE;
	ds.priority1 = 128;
	ds.clockQuality.clockClass = 248;
	ds.clockQuality.clockAccuracy = 0xfe;
	ds.clockQuality.offsetScaledLogVariance = 0xffff;
	ds.priority2 = 128;

	pod.logAnnounceInterval = 1;
	pod.logSyncInterval = 0;
	pod.logMinDelayReqInterval = 0;
	pod.logMinPdelayReqInterval = 0;
	pod.announceReceiptTimeout = 3;
	pod.transportSpecific = 0;
	pod.path_trace_enabled = 0;
	pod.follow_up_info = 0;

	if (generate_clock_identity(&ds.clockIdentity, iface[0].name)) {
		fprintf(stderr, "failed to generate a clock identity\n");
		return -1;
	}

	cfg_settings.dds = &ds;
	cfg_settings.pod = &pod;
	cfg_settings.assume_two_step = &assume_two_step;
	cfg_settings.tx_timestamp_retries = &sk_tx_retries;
	cfg_settings.rx_timestamp_l2only = &sk_prefer_layer2;
	cfg_settings.pi_proportional_const = &configured_pi_kp;
	cfg_settings.pi_integral_const = &configured_pi_ki;
	cfg_settings.ptp_dst_mac = ptp_dst_mac;
	cfg_settings.p2p_dst_mac = p2p_dst_mac;

	if (config && config_read(config, &cfg_settings)) {
		fprintf(stderr, "failed to read configuration file\n");
		return -1;
	}

	if (slaveonly) {
		ds.slaveOnly = TRUE;
		ds.clockQuality.clockClass = 255;
	}

	clock = clock_create(phc_index, iface, *nports, timestamping, &ds, &pod);
	if (!clock) {
		fprintf(stderr, "failed to create a clock\n");
		return -1;
	}

	while (running) {
		if (clock_poll(clock))
			break;
	}

	return 0;
}
