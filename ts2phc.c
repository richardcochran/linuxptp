/**
 * @file ts2phc.c
 * @brief Utility program to synchronize the PHC clock to external events
 * @note Copyright (C) 2013 Balint Ferencz <fernya@sch.bme.hu>
 * @note Based on the phc2sys utility
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <net/if.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "clockadj.h"
#include "config.h"
#include "interface.h"
#include "phc.h"
#include "print.h"
#include "ts2phc.h"
#include "version.h"

struct interface {
	STAILQ_ENTRY(interface) list;
};

static void ts2phc_cleanup(struct ts2phc_private *priv)
{
	ts2phc_pps_sink_cleanup(priv);
	if (priv->src)
		ts2phc_pps_source_destroy(priv->src);
	if (priv->cfg)
		config_destroy(priv->cfg);
}

static struct servo *ts2phc_servo_create(struct ts2phc_private *priv,
					 struct ts2phc_clock *clock)
{
	enum servo_type type = config_get_int(priv->cfg, NULL, "clock_servo");
	struct servo *servo;
	int fadj, max_adj;

	fadj = (int) clockadj_get_freq(clock->clkid);
	/* Due to a bug in older kernels, the reading may silently fail
	 * and return 0. Set the frequency back to make sure fadj is
	 * the actual frequency of the clock.
	 */
	if (!clock->no_adj) {
		clockadj_set_freq(clock->clkid, fadj);
	}

	max_adj = phc_max_adj(clock->clkid);

	servo = servo_create(priv->cfg, type, -fadj, max_adj, 0);
	if (!servo)
		return NULL;

	servo_sync_interval(servo, SERVO_SYNC_INTERVAL);

	return servo;
}

struct ts2phc_clock *ts2phc_clock_add(struct ts2phc_private *priv,
				      const char *device)
{
	clockid_t clkid = CLOCK_INVALID;
	struct ts2phc_clock *c;
	int phc_index = -1;
	int err;

	clkid = posix_clock_open(device, &phc_index);
	if (clkid == CLOCK_INVALID)
		return NULL;

	LIST_FOREACH(c, &priv->clocks, list) {
		if (c->phc_index == phc_index) {
			/* Already have the clock, don't add it again */
			posix_clock_close(clkid);
			return c;
		}
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		pr_err("failed to allocate memory for a clock");
		return NULL;
	}
	c->clkid = clkid;
	c->fd = CLOCKID_TO_FD(clkid);
	c->phc_index = phc_index;
	c->servo_state = SERVO_UNLOCKED;
	c->servo = ts2phc_servo_create(priv, c);
	c->no_adj = config_get_int(priv->cfg, NULL, "free_running");
	err = asprintf(&c->name, "/dev/ptp%d", phc_index);
	if (err < 0) {
		free(c);
		posix_clock_close(clkid);
		return NULL;
	}

	LIST_INSERT_HEAD(&priv->clocks, c, list);
	return c;
}

void ts2phc_clock_destroy(struct ts2phc_clock *c)
{
	servo_destroy(c->servo);
	posix_clock_close(c->clkid);
	free(c->name);
	free(c);
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
	int c, err = 0, have_sink = 0, index, print_level;
	enum ts2phc_pps_source_type pps_type;
	struct ts2phc_private priv = {0};
	char *config = NULL, *progname;
	const char *pps_source = NULL;
	struct config *cfg = NULL;
	struct interface *iface;
	struct option *opts;

	handle_term_signals();

	cfg = config_create();
	if (!cfg) {
		ts2phc_cleanup(&priv);
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
				ts2phc_cleanup(&priv);
				return -1;
			}
			break;
		case 'c':
			if (!config_create_interface(optarg, cfg)) {
				fprintf(stderr, "failed to add PPS sink\n");
				ts2phc_cleanup(&priv);
				return -1;
			}
			have_sink = 1;
			break;
		case 'f':
			config = optarg;
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX)) {
				ts2phc_cleanup(&priv);
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
				ts2phc_cleanup(&priv);
				return -1;
			}
			pps_source = optarg;
			break;
		case 'v':
			ts2phc_cleanup(&priv);
			version_show(stdout);
			return 0;
		case 'h':
			ts2phc_cleanup(&priv);
			usage(progname);
			return -1;
		case '?':
		default:
			ts2phc_cleanup(&priv);
			usage(progname);
			return -1;
		}
	}
	if (config && (c = config_read(config, cfg))) {
		fprintf(stderr, "failed to read config\n");
		ts2phc_cleanup(&priv);
		return -1;
	}
	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	STAILQ_INIT(&priv.sinks);
	priv.cfg = cfg;

	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		if (1 == config_get_int(cfg, interface_name(iface), "ts2phc.master")) {
			if (pps_source) {
				fprintf(stderr, "too many PPS sources\n");
				ts2phc_cleanup(&priv);
				return -1;
			}
			pps_source = interface_name(iface);
		} else {
			if (ts2phc_pps_sink_add(&priv, interface_name(iface))) {
				fprintf(stderr, "failed to add PPS sink\n");
				ts2phc_cleanup(&priv);
				return -1;
			}
			have_sink = 1;
		}
	}
	if (!have_sink) {
		fprintf(stderr, "no PPS sinks specified\n");
		ts2phc_cleanup(&priv);
		usage(progname);
		return -1;
	}
	if (!pps_source) {
		fprintf(stderr, "no PPS source specified\n");
		ts2phc_cleanup(&priv);
		usage(progname);
		return -1;
	}
	if (ts2phc_pps_sinks_init(&priv)) {
		fprintf(stderr, "failed to initialize PPS sinks\n");
		ts2phc_cleanup(&priv);
		return -1;
	}

	if (!strcasecmp(pps_source, "generic")) {
		pps_type = TS2PHC_PPS_SOURCE_GENERIC;
	} else if (!strcasecmp(pps_source, "nmea")) {
		pps_type = TS2PHC_PPS_SOURCE_NMEA;
	} else {
		pps_type = TS2PHC_PPS_SOURCE_PHC;
	}
	priv.src = ts2phc_pps_source_create(&priv, pps_source, pps_type);
	if (!priv.src) {
		fprintf(stderr, "failed to create PPS source\n");
		ts2phc_cleanup(&priv);
		return -1;
	}

	while (is_running()) {
		err = ts2phc_pps_sink_poll(&priv);
		if (err) {
			pr_err("poll failed");
			break;
		}
	}

	ts2phc_cleanup(&priv);
	return err;
}
