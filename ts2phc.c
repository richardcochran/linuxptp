/**
 * @file ts2phc.c
 * @brief Utility program to synchronize the PHC clock to external events
 * @note Copyright (C) 2013 Balint Ferencz <fernya@sch.bme.hu>
 * @note Based on the phc2sys utility
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>

#include "config.h"
#include "interface.h"
#include "print.h"
#include "ts2phc_master.h"
#include "ts2phc_slave.h"
#include "version.h"

struct interface {
	STAILQ_ENTRY(interface) list;
};

static void ts2phc_cleanup(struct config *cfg, struct ts2phc_master *master)
{
	ts2phc_slave_cleanup();
	if (master) {
		ts2phc_master_destroy(master);
	}
	if (cfg) {
		config_destroy(cfg);
	}
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\n"
		"usage: %s [options]\n\n"
		" -c [dev|name]  PHC time sink (like /dev/ptp0 or eth0)\n"
		"                (may be specified multiple times)\n"
		" -f [file]      read configuration from 'file'\n"
		" -h             prints this message and exits\n"
		" -l [num]       set the logging level to 'num'\n"
		" -m             print messages to stdout\n"
		" -q             do not print messages to the syslog\n"
		" -s [dev|name]  source of the PPS signal\n"
		"                may take any of the following forms:\n"
		"                    generic   - an external 1-PPS without ToD information\n"
		"                    /dev/ptp0 - a local PTP Hardware Clock (PHC)\n"
		"                    eth0      - a local PTP Hardware Clock (PHC)\n"
		"                    nmea      - a gps device connected by serial port or network\n"
		" -v             prints the software version and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	int c, err = 0, have_slave = 0, index, print_level;
	struct ts2phc_master *master = NULL;
	enum ts2phc_master_type pps_type;
	char *config = NULL, *progname;
	const char *pps_source = NULL;
	struct config *cfg = NULL;
	struct interface *iface;
	struct option *opts;

	handle_term_signals();

	cfg = config_create();
	if (!cfg) {
		ts2phc_cleanup(cfg, master);
		return -1;
	}

	opts = config_long_options(cfg);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1 + progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv, "c:f:hi:l:mqs:v", opts, &index))) {
		switch (c) {
		case 0:
			if (config_parse_option(cfg, opts[index].name, optarg)) {
				ts2phc_cleanup(cfg, master);
				return -1;
			}
			break;
		case 'c':
			if (!config_create_interface(optarg, cfg)) {
				fprintf(stderr, "failed to add slave\n");
				ts2phc_cleanup(cfg, master);
				return -1;
			}
			have_slave = 1;
			break;
		case 'f':
			config = optarg;
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX)) {
				ts2phc_cleanup(cfg, master);
				return -1;
			}
			config_set_int(cfg, "logging_level", print_level);
			print_set_level(print_level);
			break;
		case 'm':
			config_set_int(cfg, "verbose", 1);
			print_set_verbose(1);
			break;
		case 'q':
			config_set_int(cfg, "use_syslog", 0);
			print_set_syslog(0);
			break;
		case 's':
			if (pps_source) {
				fprintf(stderr, "too many PPS sources\n");
				ts2phc_cleanup(cfg, master);
				return -1;
			}
			pps_source = optarg;
			break;
		case 'v':
			ts2phc_cleanup(cfg, master);
			version_show(stdout);
			return 0;
		case 'h':
			ts2phc_cleanup(cfg, master);
			usage(progname);
			return -1;
		case '?':
		default:
			ts2phc_cleanup(cfg, master);
			usage(progname);
			return -1;
		}
	}
	if (config && (c = config_read(config, cfg))) {
		fprintf(stderr, "failed to read config\n");
		ts2phc_cleanup(cfg, master);
		return -1;
	}
	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		if (1 == config_get_int(cfg, interface_name(iface), "ts2phc.master")) {
			if (pps_source) {
				fprintf(stderr, "too many PPS sources\n");
				ts2phc_cleanup(cfg, master);
				return -1;
			}
			pps_source = interface_name(iface);
		} else {
			if (ts2phc_slave_add(cfg, interface_name(iface))) {
				fprintf(stderr, "failed to add slave\n");
				ts2phc_cleanup(cfg, master);
				return -1;
			}
			have_slave = 1;
		}
	}
	if (!have_slave) {
		fprintf(stderr, "no slave clocks specified\n");
		ts2phc_cleanup(cfg, master);
		usage(progname);
		return -1;
	}
	if (!pps_source) {
		fprintf(stderr, "no PPS source specified\n");
		ts2phc_cleanup(cfg, master);
		usage(progname);
		return -1;
	}
	if (ts2phc_slave_arm()) {
		fprintf(stderr, "failed to arm slaves\n");
		ts2phc_cleanup(cfg, master);
		return -1;
	}

	if (!strcasecmp(pps_source, "generic")) {
		pps_type = TS2PHC_MASTER_GENERIC;
	} else if (!strcasecmp(pps_source, "nmea")) {
		pps_type = TS2PHC_MASTER_NMEA;
	} else {
		pps_type = TS2PHC_MASTER_PHC;
	}
	master = ts2phc_master_create(cfg, pps_source, pps_type);
	if (!master) {
		fprintf(stderr, "failed to create master\n");
		ts2phc_cleanup(cfg, master);
		return -1;
	}

	while (is_running()) {
		err = ts2phc_slave_poll(master);
		if (err) {
			pr_err("poll failed");
			break;
		}
	}

	ts2phc_cleanup(cfg, master);
	return err;
}
