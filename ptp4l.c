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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/net_tstamp.h>

#include "clock.h"
#include "config.h"
#include "pi.h"
#include "print.h"
#include "raw.h"
#include "sk.h"
#include "transport.h"
#include "util.h"

int assume_two_step = 0;

static int running = 1;

static struct config cfg_settings = {
	.dds = {
		.twoStepFlag = TRUE,
		.slaveOnly = FALSE,
		.priority1 = 128,
		.clockQuality.clockClass = 248,
		.clockQuality.clockAccuracy = 0xfe,
		.clockQuality.offsetScaledLogVariance = 0xffff,
		.priority2 = 128,
		.domainNumber = 0,
		.free_running = 0,
		.freq_est_interval = 1,
	},

	.pod = {
		.logAnnounceInterval = 1,
		.logSyncInterval = 0,
		.logMinDelayReqInterval = 0,
		.logMinPdelayReqInterval = 0,
		.announceReceiptTimeout = 3,
		.transportSpecific = 0,
		.path_trace_enabled = 0,
		.follow_up_info = 0,
		.freq_est_interval = 1,
	},

	.timestamping = TS_HARDWARE,
	.dm = DM_E2E,
	.transport = TRANS_UDP_IPV4,

	.assume_two_step = &assume_two_step,
	.tx_timestamp_retries = &sk_tx_retries,

	.clock_servo = CLOCK_SERVO_PI,

	.pi_proportional_const = &configured_pi_kp,
	.pi_integral_const = &configured_pi_ki,
	.pi_offset_const = &configured_pi_offset,

	.ptp_dst_mac = ptp_dst_mac,
	.p2p_dst_mac = p2p_dst_mac,

	.print_level = LOG_INFO,
	.use_syslog = 1,
	.verbose = 0,

	.cfg_ignore = 0,
};

static void handle_int_quit_term(int s)
{
	pr_notice("caught signal %d", s);
	running = 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" Delay Mechanism\n\n"
		" -A        Auto, starting with E2E\n"
		" -E        E2E, delay request-response (default)\n"
		" -P        P2P, peer delay mechanism\n\n"
		" Network Transport\n\n"
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
	int c, i;
	struct interface *iface = cfg_settings.iface;
	char *ports[MAX_PORTS];
	int nports = 0;
	int *cfg_ignore = &cfg_settings.cfg_ignore;
	enum delay_mechanism *dm = &cfg_settings.dm;
	enum transport_type *transport = &cfg_settings.transport;
	enum timestamp_type *timestamping = &cfg_settings.timestamping;
	struct clock *clock;
	struct defaultDS *ds = &cfg_settings.dds;
	int phc_index = -1, required_modes = 0;

	if (SIG_ERR == signal(SIGINT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGINT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGQUIT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGQUIT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGTERM, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGTERM\n");
		return -1;
	}

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "AEP246HSLf:i:p:sl:qvh"))) {
		switch (c) {
		case 'A':
			*dm = DM_AUTO;
			*cfg_ignore |= CFG_IGNORE_DM;
			break;
		case 'E':
			*dm = DM_E2E;
			*cfg_ignore |= CFG_IGNORE_DM;
			break;
		case 'P':
			*dm = DM_P2P;
			*cfg_ignore |= CFG_IGNORE_DM;
			break;
		case '2':
			*transport = TRANS_IEEE_802_3;
			*cfg_ignore |= CFG_IGNORE_TRANSPORT;
			break;
		case '4':
			*transport = TRANS_UDP_IPV4;
			*cfg_ignore |= CFG_IGNORE_TRANSPORT;
			break;
		case '6':
			*transport = TRANS_UDP_IPV6;
			*cfg_ignore |= CFG_IGNORE_TRANSPORT;
			break;
		case 'H':
			*timestamping = TS_HARDWARE;
			*cfg_ignore |= CFG_IGNORE_TIMESTAMPING;
			break;
		case 'S':
			*timestamping = TS_SOFTWARE;
			*cfg_ignore |= CFG_IGNORE_TIMESTAMPING;
			break;
		case 'L':
			*timestamping = TS_LEGACY_HW;
			*cfg_ignore |= CFG_IGNORE_TIMESTAMPING;
			break;
		case 'f':
			config = optarg;
			break;
		case 'i':
			ports[nports] = optarg;
			nports++;
			break;
		case 'p':
			req_phc = optarg;
			break;
		case 's':
			ds->slaveOnly = TRUE;
			*cfg_ignore |= CFG_IGNORE_SLAVEONLY;
			break;
		case 'l':
			cfg_settings.print_level = atoi(optarg);
			*cfg_ignore |= CFG_IGNORE_PRINT_LEVEL;
			break;
		case 'q':
			cfg_settings.use_syslog = 0;
			*cfg_ignore |= CFG_IGNORE_USE_SYSLOG;
			break;
		case 'v':
			cfg_settings.verbose = 1;
			*cfg_ignore |= CFG_IGNORE_VERBOSE;
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

	if (config && (c = config_read(config, &cfg_settings))) {
		return c;
	}
	if (ds->slaveOnly) {
		ds->clockQuality.clockClass = 255;
	}

	print_set_verbose(cfg_settings.verbose);
	print_set_syslog(cfg_settings.use_syslog);
	print_set_level(cfg_settings.print_level);

	for (i = 0; i < nports; i++) {
		if (config_create_interface(ports[i], &cfg_settings) < 0) {
			fprintf(stderr, "too many interfaces\n");
			return -1;
		}
	}

	if (!cfg_settings.nports) {
		fprintf(stderr, "no interface specified\n");
		usage(progname);
		return -1;
	}

	if (*timestamping == TS_SOFTWARE)
		required_modes |= SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
	else if (*timestamping == TS_LEGACY_HW)
		required_modes |= SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_SYS_HARDWARE;
	else if (*timestamping == TS_HARDWARE)
		required_modes |= SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;

	/* check whether timestamping mode is supported. */
	for (i = 0; i < cfg_settings.nports; i++) {
		if (iface[i].ts_info.valid &&
		    !(iface[0].ts_info.so_timestamping & required_modes)) {
			fprintf(stderr, "interface '%s' does not support "
				        "requested timestamping mode.\n",
				iface[i].name);
			return -1;
		}
	}

	/* determine PHC Clock index */
	if (ds->free_running) {
		phc_index = -1;
	} else if (*timestamping == TS_SOFTWARE || *timestamping == TS_LEGACY_HW) {
		phc_index = -1;
	} else if (req_phc) {
		if (1 != sscanf(req_phc, "/dev/ptp%d", &phc_index)) {
			fprintf(stderr, "bad ptp device string\n");
			return -1;
		}
	} else if (iface[0].ts_info.valid) {
		phc_index = iface[0].ts_info.phc_index;
	} else {
		fprintf(stderr, "ptp device not specified and\n"
			        "automatic determination is not\n"
			        "supported. please specify ptp device\n");
		return -1;
	}

	if (phc_index >= 0) {
		pr_info("selected /dev/ptp%d as PTP clock", phc_index);
	}

	if (generate_clock_identity(&ds->clockIdentity, iface[0].name)) {
		fprintf(stderr, "failed to generate a clock identity\n");
		return -1;
	}

	clock = clock_create(phc_index, iface, cfg_settings.nports,
			     *timestamping, ds, cfg_settings.clock_servo);
	if (!clock) {
		fprintf(stderr, "failed to create a clock\n");
		return -1;
	}

	while (running) {
		if (clock_poll(clock))
			break;
	}

	clock_destroy(clock);
	return 0;
}
