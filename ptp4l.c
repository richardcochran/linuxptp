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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/net_tstamp.h>

#include "clock.h"
#include "config.h"
#include "ntpshm.h"
#include "pi.h"
#include "print.h"
#include "raw.h"
#include "sk.h"
#include "transport.h"
#include "udp6.h"
#include "uds.h"
#include "util.h"
#include "version.h"

int assume_two_step = 0;

static struct default_ds ptp4l_dds;

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
		" -m        print messages to stdout\n"
		" -q        do not print messages to the syslog\n"
		" -v        prints the software version and exits\n"
		" -h        prints this message and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *config = NULL, *req_phc = NULL, *progname, *tmp;
	int c, err = -1;
	struct interface *iface;
	struct clock *clock = NULL;
	struct config *cfg;
	struct default_ds *dds = &ptp4l_dds;
	struct defaultDS *ds = &ptp4l_dds.dds;
	int phc_index = -1, print_level, required_modes = 0;
	unsigned char oui[OUI_LEN];

	if (handle_term_signals())
		return -1;

	cfg = config_create();
	if (!cfg) {
		return -1;
	}

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "AEP246HSLf:i:p:sl:mqvh"))) {
		switch (c) {
		case 'A':
			if (config_set_int(cfg, "delay_mechanism", DM_AUTO))
				goto out;
			break;
		case 'E':
			if (config_set_int(cfg, "delay_mechanism", DM_E2E))
				goto out;
			break;
		case 'P':
			if (config_set_int(cfg, "delay_mechanism", DM_P2P))
				goto out;
			break;
		case '2':
			if (config_set_int(cfg, "network_transport",
					    TRANS_IEEE_802_3))
				goto out;
			break;
		case '4':
			if (config_set_int(cfg, "network_transport",
					    TRANS_UDP_IPV4))
				goto out;
			break;
		case '6':
			if (config_set_int(cfg, "network_transport",
					    TRANS_UDP_IPV6))
				goto out;
			break;
		case 'H':
			if (config_set_int(cfg, "time_stamping", TS_HARDWARE))
				goto out;
			break;
		case 'S':
			if (config_set_int(cfg, "time_stamping", TS_SOFTWARE))
				goto out;
			break;
		case 'L':
			if (config_set_int(cfg, "time_stamping", TS_LEGACY_HW))
				goto out;
			break;
		case 'f':
			config = optarg;
			break;
		case 'i':
			if (!config_create_interface(optarg, cfg))
				goto out;
			break;
		case 'p':
			req_phc = optarg;
			break;
		case 's':
			if (config_set_int(cfg, "slaveOnly", 1)) {
				goto out;
			}
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX))
				goto out;
			config_set_int(cfg, "logging_level", print_level);
			break;
		case 'm':
			config_set_int(cfg, "verbose", 1);
			break;
		case 'q':
			config_set_int(cfg, "use_syslog", 0);
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'h':
			usage(progname);
			return 0;
		case '?':
			usage(progname);
			goto out;
		default:
			usage(progname);
			goto out;
		}
	}

	if (config && (c = config_read(config, cfg))) {
		return c;
	}

	print_set_progname(progname);
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	assume_two_step = config_get_int(cfg, NULL, "assume_two_step");
	sk_check_fupsync = config_get_int(cfg, NULL, "check_fup_sync");
	sk_tx_timeout = config_get_int(cfg, NULL, "tx_timestamp_timeout");

	ds->clockQuality.clockClass = config_get_int(cfg, NULL, "clockClass");
	ds->clockQuality.clockAccuracy = config_get_int(cfg, NULL, "clockAccuracy");
	ds->clockQuality.offsetScaledLogVariance =
		config_get_int(cfg, NULL, "offsetScaledLogVariance");

	dds->clock_desc.productDescription.max_symbols = 64;
	dds->clock_desc.revisionData.max_symbols = 32;
	dds->clock_desc.userDescription.max_symbols = 128;

	tmp = config_get_string(cfg, NULL, "productDescription");
	if (count_char(tmp, ';') != 2 ||
	    static_ptp_text_set(&dds->clock_desc.productDescription, tmp)) {
		fprintf(stderr, "invalid productDescription '%s'.\n", tmp);
		goto out;
	}
	tmp = config_get_string(cfg, NULL, "revisionData");
	if (count_char(tmp, ';') != 2 ||
	    static_ptp_text_set(&dds->clock_desc.revisionData, tmp)) {
		fprintf(stderr, "invalid revisionData '%s'.\n", tmp);
		goto out;
	}
	tmp = config_get_string(cfg, NULL, "userDescription");
	if (static_ptp_text_set(&dds->clock_desc.userDescription, tmp)) {
		fprintf(stderr, "invalid userDescription '%s'.\n", tmp);
		goto out;
	}
	tmp = config_get_string(cfg, NULL, "manufacturerIdentity");
	if (OUI_LEN != sscanf(tmp, "%hhx:%hhx:%hhx", &oui[0], &oui[1], &oui[2])) {
		fprintf(stderr, "invalid manufacturerIdentity '%s'.\n", tmp);
		goto out;
	}
	memcpy(dds->clock_desc.manufacturerIdentity, oui, OUI_LEN);

	ds->domainNumber = config_get_int(cfg, NULL, "domainNumber");

	if (config_get_int(cfg, NULL, "slaveOnly")) {
	    ds->flags |= DDS_SLAVE_ONLY;
	    ds->clockQuality.clockClass = 248;
	}
	if (config_get_int(cfg, NULL, "twoStepFlag")) {
	    ds->flags |= DDS_TWO_STEP_FLAG;
	}
	ds->priority1 = config_get_int(cfg, NULL, "priority1");
	ds->priority2 = config_get_int(cfg, NULL, "priority2");

	if (!config_get_int(cfg, NULL, "gmCapable") &&
	    ds->flags & DDS_SLAVE_ONLY) {
		fprintf(stderr,
			"Cannot mix 1588 slaveOnly with 802.1AS !gmCapable.\n");
		goto out;
	}
	if (!config_get_int(cfg, NULL, "gmCapable") ||
	    ds->flags & DDS_SLAVE_ONLY) {
		ds->clockQuality.clockClass = 255;
	}
	if (config_get_int(cfg, NULL, "clock_servo") == CLOCK_SERVO_NTPSHM) {
		config_set_int(cfg, "kernel_leap", 0);
		config_set_int(cfg, "sanity_freq_limit", 0);
	}

	if (STAILQ_EMPTY(&cfg->interfaces)) {
		fprintf(stderr, "no interface specified\n");
		usage(progname);
		goto out;
	}

	if (!(ds->flags & DDS_TWO_STEP_FLAG)) {
		switch (config_get_int(cfg, NULL, "time_stamping")) {
		case TS_SOFTWARE:
		case TS_LEGACY_HW:
			fprintf(stderr, "one step is only possible "
				"with hardware time stamping\n");
			goto out;
		case TS_HARDWARE:
			if (config_set_int(cfg, "time_stamping", TS_ONESTEP))
				goto out;
			break;
		case TS_ONESTEP:
			break;
		}
	}

	switch (config_get_int(cfg, NULL, "time_stamping")) {
	case TS_SOFTWARE:
		required_modes |= SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
		break;
	case TS_LEGACY_HW:
		required_modes |= SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_SYS_HARDWARE;
		break;
	case TS_HARDWARE:
	case TS_ONESTEP:
		required_modes |= SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;
		break;
	}

	/* Init interface configs and check whether timestamping mode is
	 * supported. */
	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		config_init_interface(iface, cfg);
		if (iface->ts_info.valid &&
		    ((iface->ts_info.so_timestamping & required_modes) != required_modes)) {
			fprintf(stderr, "interface '%s' does not support "
				        "requested timestamping mode.\n",
				iface->name);
			goto out;
		}
	}

	/* determine PHC Clock index */
	iface = STAILQ_FIRST(&cfg->interfaces);
	if (config_get_int(cfg, NULL, "free_running")) {
		phc_index = -1;
	} else if (config_get_int(cfg, NULL, "time_stamping") == TS_SOFTWARE ||
		   config_get_int(cfg, NULL, "time_stamping") == TS_LEGACY_HW) {
		phc_index = -1;
	} else if (req_phc) {
		if (1 != sscanf(req_phc, "/dev/ptp%d", &phc_index)) {
			fprintf(stderr, "bad ptp device string\n");
			goto out;
		}
	} else if (iface->ts_info.valid) {
		phc_index = iface->ts_info.phc_index;
	} else {
		fprintf(stderr, "ptp device not specified and\n"
			        "automatic determination is not\n"
			        "supported. please specify ptp device\n");
		goto out;
	}

	if (phc_index >= 0) {
		pr_info("selected /dev/ptp%d as PTP clock", phc_index);
	}

	if (generate_clock_identity(&ds->clockIdentity, iface->name)) {
		fprintf(stderr, "failed to generate a clock identity\n");
		goto out;
	}

	clock = clock_create(cfg, phc_index, &cfg->interfaces, &ptp4l_dds);
	if (!clock) {
		fprintf(stderr, "failed to create a clock\n");
		goto out;
	}

	err = 0;

	while (is_running()) {
		if (clock_poll(clock))
			break;
	}
out:
	if (clock)
		clock_destroy(clock);
	config_destroy(cfg);
	return err;
}
