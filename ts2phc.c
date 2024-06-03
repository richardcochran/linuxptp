/**
 * @file ts2phc.c
 * @brief Utility program to synchronize the PHC clock to external events
 * @note Copyright (C) 2013 Balint Ferencz <fernya@sch.bme.hu>
 * @note Based on the phc2sys utility
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "clockadj.h"
#include "config.h"
#include "contain.h"
#include "interface.h"
#include "phc.h"
#include "print.h"
#include "sad.h"
#include "ts2phc.h"
#include "version.h"

#define NS_PER_SEC		1000000000LL
#define SAMPLE_WEIGHT		1.0

struct interface {
	STAILQ_ENTRY(interface) list;
};

static void ts2phc_cleanup(struct ts2phc_private *priv)
{
	struct ts2phc_port *p, *tmp;

	ts2phc_pps_sink_cleanup(priv);
	if (priv->src)
		ts2phc_pps_source_destroy(priv->src);
	if (priv->cfg) {
		sad_destroy(priv->cfg);
		config_destroy(priv->cfg);
	}
	if (priv->agent)
		pmc_agent_destroy(priv->agent);

	/*
	 * Clocks are destroyed by the cleanup methods of the individual
	 * PPS source and sink modules.
	 */
	LIST_FOREACH_SAFE(p, &priv->ports, list, tmp)
		free(p);

	msg_cleanup();
}

static struct ts2phc_port *ts2phc_port_get(struct ts2phc_private *priv,
					   unsigned int number)
{
	struct ts2phc_port *p;

	LIST_FOREACH(p, &priv->ports, list)
		if (p->number == number)
			return p;

	return NULL;
}

static enum port_state ts2phc_clock_compute_state(struct ts2phc_private *priv,
						  struct ts2phc_clock *clock)
{
	enum port_state state = PS_DISABLED;
	struct ts2phc_port *p;

	LIST_FOREACH(p, &priv->ports, list) {
		if (p->clock != clock)
			continue;
		/* PS_SLAVE takes the highest precedence, PS_UNCALIBRATED
		 * after that, PS_MASTER is third, PS_PRE_MASTER fourth and
		 * all of that overrides PS_DISABLED, which corresponds
		 * nicely with the numerical values */
		if (p->state > state)
			state = p->state;
	}
	return state;
}

static int ts2phc_recv_subscribed(void *context, struct ptp_message *msg,
				  int excluded)
{
	struct ts2phc_private *priv = context;
	enum port_state state;
	struct ts2phc_clock *clock;
	struct portDS *pds;
	struct ts2phc_port *port;
	int mgt_id;

	mgt_id = management_tlv_id(msg);
	if (mgt_id == excluded)
		return 0;

	switch (mgt_id) {
	case MID_PORT_DATA_SET:
		pds = management_tlv_data(msg);
		port = ts2phc_port_get(priv, pds->portIdentity.portNumber);
		if (!port) {
			pr_info("received data for unknown port %s",
				pid2str(&pds->portIdentity));
			return 1;
		}
		state = port_state_normalize(pds->portState);
		if (port->state != state) {
			pr_info("port %s changed state",
				pid2str(&pds->portIdentity));
			port->state = state;
			clock = port->clock;
			state = ts2phc_clock_compute_state(priv, clock);
			if (clock->state != state || clock->new_state) {
				clock->new_state = state;
				priv->state_changed = true;
			}
		}
		return 1;
	}
	return 0;
}

static struct servo *ts2phc_servo_create(struct ts2phc_private *priv,
					 struct ts2phc_clock *clock)
{
	enum servo_type type = config_get_int(priv->cfg, NULL, "clock_servo");
	struct servo *servo;
	double fadj;
	int max_adj;

	fadj = clockadj_get_freq(clock->clkid);

	max_adj = phc_max_adj(clock->clkid);

	servo = servo_create(priv->cfg, type, -fadj, max_adj, 0);
	if (!servo)
		return NULL;

	servo_sync_interval(servo, SERVO_SYNC_INTERVAL);

	return servo;
}

void ts2phc_clock_add_tstamp(struct ts2phc_clock *clock, tmv_t t)
{
	struct timespec ts = tmv_to_timespec(t);

	pr_debug("adding tstamp %ld.%09ld to clock %s",
		 ts.tv_sec, ts.tv_nsec, clock->name);
	clock->last_ts = t;
	clock->is_ts_available = true;
}

static int ts2phc_clock_get_tstamp(struct ts2phc_clock *clock, tmv_t *ts)
{
	if (!clock->is_ts_available)
		return 0;
	clock->is_ts_available = false;
	*ts = clock->last_ts;
	return 1;
}

static void ts2phc_clock_flush_tstamp(struct ts2phc_clock *clock)
{
	clock->is_ts_available = false;
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

static struct ts2phc_port *ts2phc_port_add(struct ts2phc_private *priv,
					   unsigned int number, char *device)
{
	struct ts2phc_clock *c = NULL;
	struct ts2phc_port *p, *tmp;

	p = ts2phc_port_get(priv, number);
	if (p)
		return p;
	/* port is a new one, look whether we have the device already
	 * on a different port
	 */
	LIST_FOREACH(tmp, &priv->ports, list) {
		if (tmp->number == number) {
			c = tmp->clock;
			break;
		}
	}
	if (!c) {
		c = ts2phc_clock_add(priv, device);
		if (!c)
			return NULL;
	}
	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("failed to allocate memory for a port");
		ts2phc_clock_destroy(c);
		return NULL;
	}
	p->number = number;
	p->clock = c;
	LIST_INSERT_HEAD(&priv->ports, p, list);
	return p;
}

static int ts2phc_auto_init_ports(struct ts2phc_private *priv)
{
	int number_ports, timestamping, phc_index, err;
	struct ts2phc_clock *clock;
	struct ts2phc_port *port;
	enum port_state state;
	char iface[IFNAMSIZ];
	unsigned int i;

	while (1) {
		if (!is_running())
			return -1;
		err = pmc_agent_query_dds(priv->agent, 1000);
		if (!err)
			break;
		if (err == -ETIMEDOUT)
			pr_notice("Waiting for ptp4l...");
		else
			return -1;
	}

	number_ports = pmc_agent_get_number_ports(priv->agent);
	if (number_ports <= 0) {
		pr_err("failed to get number of ports");
		return -1;
	}

	err = pmc_agent_subscribe(priv->agent, 1000, 1);
	if (err) {
		pr_err("failed to subscribe");
		return -1;
	}

	for (i = 1; i <= number_ports; i++) {
		err = pmc_agent_query_port_properties(priv->agent, 1000, i,
						      &state, &timestamping,
						      &phc_index, iface);
		if (err == -ENODEV) {
			/* port does not exist, ignore the port */
			continue;
		}
		if (err) {
			pr_err("failed to get port properties");
			return -1;
		}
		if (timestamping == TS_SOFTWARE) {
			/* ignore ports with software time stamping */
			continue;
		}
		port = ts2phc_port_add(priv, i, iface);
		if (!port)
			return -1;
		port->state = port_state_normalize(state);
	}
	if (LIST_EMPTY(&priv->clocks)) {
		pr_err("no suitable ports available");
		return -1;
	}
	LIST_FOREACH(clock, &priv->clocks, list) {
		clock->new_state = ts2phc_clock_compute_state(priv, clock);
	}
	priv->state_changed = true;

	return 0;
}

static void ts2phc_reconfigure(struct ts2phc_private *priv)
{
	struct ts2phc_clock *c, *ref_clk = NULL, *last = NULL;
	int num_ref_clocks = 0, num_target_clocks = 0;

	pr_info("reconfiguring after port state change");
	priv->state_changed = false;

	LIST_FOREACH(c, &priv->clocks, list) {
		if (c->new_state) {
			c->state = c->new_state;
			c->new_state = 0;
		}

		switch (c->state) {
		case PS_FAULTY:
		case PS_DISABLED:
		case PS_LISTENING:
		case PS_PRE_MASTER:
		case PS_MASTER:
		case PS_PASSIVE:
			if (!c->is_target) {
				pr_info("selecting %s for synchronization",
					c->name);
				c->is_target = true;
			}
			num_target_clocks++;
			break;
		case PS_UNCALIBRATED:
			num_ref_clocks++;
			break;
		case PS_SLAVE:
			ref_clk = c;
			num_ref_clocks++;
			break;
		default:
			break;
		}
		last = c;
	}
	if (num_target_clocks >= 1 && !ref_clk) {
		priv->ref_clock = last;
		priv->ref_clock->is_target = false;
		/* Reset to original state in next reconfiguration. */
		priv->ref_clock->new_state = priv->ref_clock->state;
		priv->ref_clock->state = PS_SLAVE;
		pr_info("no reference clock, selecting %s by default",
			last->name);
		return;
	}
	if (num_ref_clocks > 1) {
		pr_info("multiple reference clocks available, postponing sync...");
		priv->ref_clock = NULL;
		return;
	}
	if (num_ref_clocks > 0 && !ref_clk) {
		pr_info("reference clock not ready, waiting...");
		priv->ref_clock = NULL;
		return;
	}
	if (!num_ref_clocks && !num_target_clocks) {
		pr_info("no PHC ready, waiting...");
		priv->ref_clock = NULL;
		return;
	}
	if (!num_ref_clocks) {
		pr_info("nothing to synchronize");
		priv->ref_clock = NULL;
		return;
	}
	ref_clk->is_target = false;
	priv->ref_clock = ref_clk;
	pr_info("selecting %s as the reference clock", ref_clk->name);
}

static int ts2phc_pps_source_implicit_tstamp(struct ts2phc_private *priv,
					     tmv_t *source_tmv)
{
	struct timespec source_ts;
	tmv_t tmv;
	int err;

	err = ts2phc_pps_source_getppstime(priv->src, &source_ts);
	if (err < 0) {
		pr_err("source ts not valid");
		return err;
	}

	tmv = timespec_to_tmv(source_ts);
	tmv = tmv_sub(tmv, priv->perout_phase);
	source_ts = tmv_to_timespec(tmv);

	/*
	 * As long as the kernel doesn't support a proper API for reporting
	 * back a precise perout timestamp, we'll have to implicitly assume
	 * assumption that the current time on the PPS source is still within
	 * +/- half a second of the past perout output edge, and hence, we can
	 * deduce the timestamp (actually only seconds part, nanoseconds are by
	 * construction zero) of this edge at the emitter based on the
	 * emitter's current time.
	 *
	 * With an NMEA source assume its messages always follow the pulse, i.e.
	 * assign the timestamp to the previous pulse instead of nearest pulse.
	 */
	if (ts2phc_pps_source_get_type(priv->src) == TS2PHC_PPS_SOURCE_NMEA) {
		source_ts.tv_sec++;
	} else {
		if (source_ts.tv_nsec > NS_PER_SEC / 2)
			source_ts.tv_sec++;
	}
	source_ts.tv_nsec = 0;

	tmv = timespec_to_tmv(source_ts);
	tmv = tmv_add(tmv, priv->perout_phase);

	*source_tmv = tmv;

	return 0;
}

static void ts2phc_synchronize_clocks(struct ts2phc_private *priv, int autocfg)
{
	struct timespec source_ts, now;
	tmv_t source_tmv;
	struct ts2phc_clock *c;
	int holdover, valid;

	if (autocfg) {
		if (!priv->ref_clock) {
			pr_debug("no reference clock, skipping");
			return;
		}
		valid = ts2phc_clock_get_tstamp(priv->ref_clock, &source_tmv);
		if (!valid) {
			pr_err("reference clock (%s) timestamp not valid, skipping",
				priv->ref_clock->name);
			return;
		}
	} else {
		valid = !ts2phc_pps_source_implicit_tstamp(priv, &source_tmv);
	}

	if (valid) {
		priv->holdover_start = 0;
		holdover = 0;
	} else {
		clock_gettime(CLOCK_MONOTONIC, &now);

		if (!priv->holdover_start)
			priv->holdover_start = now.tv_sec;
		if (now.tv_sec >= priv->holdover_start + priv->holdover_length)
			return;
		holdover = 1;
	}

	LIST_FOREACH(c, &priv->clocks, list) {
		int64_t offset;
		double adj;
		tmv_t ts;

		if (!c->is_target)
			continue;

		valid = ts2phc_clock_get_tstamp(c, &ts);
		if (!valid) {
			pr_debug("%s timestamp not valid, skipping", c->name);
			continue;
		}

		if (holdover) {
			if (c->servo_state != SERVO_LOCKED_STABLE)
				continue;
			source_ts = tmv_to_timespec(ts);
			if (source_ts.tv_nsec > NS_PER_SEC / 2)
				source_ts.tv_sec++;
			source_ts.tv_nsec = 0;
			source_tmv = timespec_to_tmv(source_ts);
		}

		offset = tmv_to_nanoseconds(tmv_sub(ts, source_tmv));

		if (c->no_adj) {
			pr_info("%s offset %10" PRId64, c->name,
				offset);
			continue;
		}

		adj = servo_sample(c->servo, offset, tmv_to_nanoseconds(ts),
				   SAMPLE_WEIGHT, &c->servo_state);

		if (holdover && c->servo_state != SERVO_LOCKED_STABLE) {
			pr_info("%s lost holdover lock (offset %10" PRId64 ")",
				c->name, offset);
			continue;
		}

		pr_info("%s offset %10" PRId64 " s%d freq %+7.0f%s",
			c->name, offset, c->servo_state, adj,
			holdover ? " holdover" : "");

		switch (c->servo_state) {
		case SERVO_UNLOCKED:
			break;
		case SERVO_JUMP:
			if (clockadj_set_freq(c->clkid, -adj)) {
				goto servo_unlock;
			}
			if (clockadj_step(c->clkid, -offset)) {
				goto servo_unlock;
			}
			break;
		case SERVO_LOCKED:
		case SERVO_LOCKED_STABLE:
			if (clockadj_set_freq(c->clkid, -adj)) {
				goto servo_unlock;
			}
			break;
		}
		continue;

servo_unlock:
		servo_reset(c->servo);
		c->servo_state = SERVO_UNLOCKED;
	}
}

static int ts2phc_collect_pps_source_tstamp(struct ts2phc_private *priv)
{
	struct ts2phc_clock *pps_src_clock;
	tmv_t source_tmv;
	int err;

	pps_src_clock = ts2phc_pps_source_get_clock(priv->src);
	/*
	 * PPS source isn't a PHC (it may be a generic or a GPS PPS source),
	 * don't error out, just don't do anything. If it doesn't have a PHC,
	 * there is nothing to synchronize, which is the only point of
	 * collecting its perout timestamp in the first place.
	 */
	if (!pps_src_clock)
		return 0;

	err = ts2phc_pps_source_implicit_tstamp(priv, &source_tmv);
	if (err < 0)
		return err;

	ts2phc_clock_add_tstamp(pps_src_clock, source_tmv);

	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\n"
		"usage: %s [options]\n\n"
		" -a             turn on autoconfiguration\n"
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
	int c, err = 0, have_sink = 0, index, cmd_line_print_level;
	char uds_local[MAX_IFNAME_SIZE + 1];
	enum ts2phc_pps_source_type pps_type;
	struct ts2phc_private priv = {0};
	char *config = NULL, *progname;
	const char *tod_source = NULL;
	struct config *cfg = NULL;
	struct interface *iface;
	struct option *opts;
	int autocfg = 0;

	handle_term_signals();

	cfg = config_create();
	if (!cfg) {
		ts2phc_cleanup(&priv);
		return -1;
	}
	priv.cfg = cfg;
	priv.agent = pmc_agent_create();
	if (!priv.agent) {
		ts2phc_cleanup(&priv);
		return -1;
	}

	opts = config_long_options(cfg);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1 + progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv, "ac:f:hi:l:mqs:v", opts, &index))) {
		switch (c) {
		case 0:
			if (config_parse_option(cfg, opts[index].name, optarg)) {
				ts2phc_cleanup(&priv);
				return -1;
			}
			break;
		case 'a':
			autocfg = 1;
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
			if (get_arg_val_i(c, optarg, &cmd_line_print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX)) {
				ts2phc_cleanup(&priv);
				return -1;
			}
			config_set_int(cfg, "logging_level", cmd_line_print_level);
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
			if (tod_source) {
				fprintf(stderr, "too many PPS sources\n");
				ts2phc_cleanup(&priv);
				return -1;
			}
			tod_source = optarg;
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

	if (sad_create(cfg)) {
		fprintf(stderr, "failed to get security associations\n");
		ts2phc_cleanup(&priv);
		return -1;
	}

	snprintf(uds_local, sizeof(uds_local), "/var/run/ts2phc.%d",
		 getpid());

	if (autocfg) {
		err = init_pmc_node(cfg, priv.agent, uds_local,
				    ts2phc_recv_subscribed, &priv);
		if (err) {
			ts2phc_cleanup(&priv);
			return -1;
		}
		err = ts2phc_auto_init_ports(&priv);
		if (err) {
			ts2phc_cleanup(&priv);
			return -1;
		}
	}

	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		const char *dev = interface_name(iface);

		if (1 == config_get_int(cfg, dev, "ts2phc.master")) {
			int perout_phase;

			if (tod_source) {
				fprintf(stderr, "too many PPS sources\n");
				ts2phc_cleanup(&priv);
				return -1;
			}
			tod_source = dev;
			perout_phase = config_get_int(cfg, dev,
						      "ts2phc.perout_phase");
			/*
			 * We use a default value of -1 to distinguish whether
			 * to use the PTP_PEROUT_PHASE API or not. But if we
			 * don't use that (and therefore we use absolute start
			 * time), the phase is still zero, by our application's
			 * convention.
			 */
			if (perout_phase < 0)
				perout_phase = 0;
			priv.perout_phase = nanoseconds_to_tmv(perout_phase);
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

	if (!tod_source)
		tod_source = config_get_string(cfg, NULL, "ts2phc.tod_source");

	if (ts2phc_pps_sinks_init(&priv)) {
		fprintf(stderr, "failed to initialize PPS sinks\n");
		ts2phc_cleanup(&priv);
		return -1;
	}

	if (!strcasecmp(tod_source, "generic")) {
		pps_type = TS2PHC_PPS_SOURCE_GENERIC;
	} else if (!strcasecmp(tod_source, "nmea")) {
		pps_type = TS2PHC_PPS_SOURCE_NMEA;
	} else {
		pps_type = TS2PHC_PPS_SOURCE_PHC;
	}
	priv.src = ts2phc_pps_source_create(&priv, tod_source, pps_type);
	if (!priv.src) {
		fprintf(stderr, "failed to create PPS source\n");
		ts2phc_cleanup(&priv);
		return -1;
	}

	priv.holdover_length = config_get_int(cfg, NULL, "ts2phc.holdover");
	priv.holdover_start = 0;

	while (is_running()) {
		struct ts2phc_clock *clk;

		if (autocfg) {
			/* Collect updates from ptp4l */
			err = pmc_agent_update(priv.agent);
			if (err < 0) {
				pr_err("pmc_agent_update returned %d", err);
				break;
			}

			if (priv.state_changed)
				ts2phc_reconfigure(&priv);
		}

		LIST_FOREACH(clk, &priv.clocks, list)
			ts2phc_clock_flush_tstamp(clk);

		err = ts2phc_pps_sink_poll(&priv);
		if (err < 0) {
			pr_err("poll failed");
			break;
		}
		if (err > 0) {
			err = ts2phc_collect_pps_source_tstamp(&priv);
			if (err) {
				pr_err("failed to collect PPS source tstamp");
				break;
			}

			ts2phc_synchronize_clocks(&priv, autocfg);
		}
	}

	ts2phc_cleanup(&priv);
	return err;
}
