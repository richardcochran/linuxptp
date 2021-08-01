/**
 * @file phc2sys.c
 * @brief Utility program to synchronize two clocks via a PPS.
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
#include <fcntl.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/pps.h>
#include <linux/ptp_clock.h>

#include "clockadj.h"
#include "clockcheck.h"
#include "contain.h"
#include "ds.h"
#include "fsm.h"
#include "missing.h"
#include "notification.h"
#include "ntpshm.h"
#include "phc.h"
#include "pi.h"
#include "pmc_agent.h"
#include "print.h"
#include "servo.h"
#include "sk.h"
#include "stats.h"
#include "sysoff.h"
#include "tlv.h"
#include "uds.h"
#include "util.h"
#include "version.h"

#define KP 0.7
#define KI 0.3
#define NS_PER_SEC 1000000000LL

#define PHC_PPS_OFFSET_LIMIT 10000000

struct clock {
	LIST_ENTRY(clock) list;
	LIST_ENTRY(clock) dst_list;
	clockid_t clkid;
	int phc_index;
	int sysoff_method;
	int is_utc;
	int dest_only;
	int state;
	int new_state;
	int sync_offset;
	int leap_set;
	int utc_offset_set;
	struct servo *servo;
	enum servo_state servo_state;
	char *device;
	const char *source_label;
	struct stats *offset_stats;
	struct stats *freq_stats;
	struct stats *delay_stats;
	struct clockcheck *sanity_check;
};

struct port {
	LIST_ENTRY(port) list;
	unsigned int number;
	int state;
	struct clock *clock;
};

struct phc2sys_private {
	unsigned int stats_max_count;
	int sanity_freq_limit;
	enum servo_type servo_type;
	int phc_readings;
	double phc_interval;
	int forced_sync_offset;
	int kernel_leap;
	int state_changed;
	struct pmc_agent *agent;
	LIST_HEAD(port_head, port) ports;
	LIST_HEAD(clock_head, clock) clocks;
	LIST_HEAD(dst_clock_head, clock) dst_clocks;
	struct clock *master;
};

static struct config *phc2sys_config;

static int clock_handle_leap(struct phc2sys_private *priv,
			     struct clock *clock,
			     int64_t offset, uint64_t ts);

static int normalize_state(int state);

static struct servo *servo_add(struct phc2sys_private *priv,
			       struct clock *clock)
{
	double ppb;
	int max_ppb;
	struct servo *servo;

	clockadj_init(clock->clkid);
	ppb = clockadj_get_freq(clock->clkid);
	/* The reading may silently fail and return 0, reset the frequency to
	   make sure ppb is the actual frequency of the clock. */
	clockadj_set_freq(clock->clkid, ppb);
	if (clock->clkid == CLOCK_REALTIME) {
		sysclk_set_leap(0);
		max_ppb = sysclk_max_freq();
	} else {
		max_ppb = phc_max_adj(clock->clkid);
		if (!max_ppb) {
			pr_err("clock is not adjustable");
			return NULL;
		}
	}

	servo = servo_create(phc2sys_config, priv->servo_type,
			     -ppb, max_ppb, 0);
	if (!servo) {
		pr_err("Failed to create servo");
		return NULL;
	}

	servo_sync_interval(servo, priv->phc_interval);

	return servo;
}

static struct clock *clock_add(struct phc2sys_private *priv, const char *device)
{
	struct clock *c;
	clockid_t clkid = CLOCK_INVALID;
	int phc_index = -1;

	if (device) {
		clkid = posix_clock_open(device, &phc_index);
		if (clkid == CLOCK_INVALID)
			return NULL;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		pr_err("failed to allocate memory for a clock");
		return NULL;
	}
	c->clkid = clkid;
	c->phc_index = phc_index;
	c->servo_state = SERVO_UNLOCKED;
	c->device = device ? strdup(device) : NULL;

	if (c->clkid == CLOCK_REALTIME) {
		c->source_label = "sys";
		c->is_utc = 1;
	} else {
		c->source_label = "phc";
	}

	if (priv->stats_max_count > 0) {
		c->offset_stats = stats_create();
		c->freq_stats = stats_create();
		c->delay_stats = stats_create();
		if (!c->offset_stats ||
		    !c->freq_stats ||
		    !c->delay_stats) {
			pr_err("failed to create stats");
			return NULL;
		}
	}
	if (priv->sanity_freq_limit) {
		c->sanity_check = clockcheck_create(priv->sanity_freq_limit);
		if (!c->sanity_check) {
			pr_err("failed to create clock check");
			return NULL;
		}
	}

	if (clkid != CLOCK_INVALID && clkid != CLOCK_REALTIME)
		c->sysoff_method = sysoff_probe(CLOCKID_TO_FD(clkid),
						priv->phc_readings);

	LIST_INSERT_HEAD(&priv->clocks, c, list);
	return c;
}

static void clock_cleanup(struct phc2sys_private *priv)
{
	struct clock *c, *tmp;

	LIST_FOREACH_SAFE(c, &priv->clocks, list, tmp) {
		if (c->servo) {
			servo_destroy(c->servo);
		}
		if (c->sanity_check) {
			clockcheck_destroy(c->sanity_check);
		}
		if (c->delay_stats) {
			stats_destroy(c->delay_stats);
		}
		if (c->freq_stats) {
			stats_destroy(c->freq_stats);
		}
		if (c->offset_stats) {
			stats_destroy(c->offset_stats);
		}
		if (c->device) {
			free(c->device);
		}
		free(c);
	}
}

static void port_cleanup(struct phc2sys_private *priv)
{
	struct port *p, *tmp;

	LIST_FOREACH_SAFE(p, &priv->ports, list, tmp) {
		free(p);
	}
}

static struct port *port_get(struct phc2sys_private *priv, unsigned int number)
{
	struct port *p;

	LIST_FOREACH(p, &priv->ports, list) {
		if (p->number == number)
			return p;
	}
	return NULL;
}

static struct port *port_add(struct phc2sys_private *priv, unsigned int number,
			     char *device)
{
	struct port *p;
	struct clock *c = NULL, *tmp;

	p = port_get(priv, number);
	if (p)
		return p;
	/* port is a new one, look whether we have the device already on
	 * a different port */
	LIST_FOREACH(tmp, &priv->clocks, list) {
		if (!strcmp(tmp->device, device)) {
			c = tmp;
			break;
		}
	}
	if (!c) {
		c = clock_add(priv, device);
		if (!c)
			return NULL;
	}
	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("failed to allocate memory for a port");
		return NULL;
	}
	p->number = number;
	p->clock = c;
	LIST_INSERT_HEAD(&priv->ports, p, list);
	return p;
}

static void clock_reinit(struct phc2sys_private *priv, struct clock *clock,
			 int new_state)
{
	int err = -1, phc_index = -1, phc_switched = 0, state, timestamping;
	struct port *p;
	struct sk_ts_info ts_info;
	char iface[IFNAMSIZ];
	clockid_t clkid = CLOCK_INVALID;

	LIST_FOREACH(p, &priv->ports, list) {
		if (p->clock != clock) {
			continue;
		}
		err = pmc_agent_query_port_properties(priv->agent, 1000,
						      p->number, &state,
						      &timestamping, iface);
		if (!err) {
			p->state = normalize_state(state);
		}
		break;
	}

	if (!err && timestamping != TS_SOFTWARE) {
		/* Check if device changed */
		if (strcmp(clock->device, iface)) {
			free(clock->device);
			clock->device = strdup(iface);
		}
		/* Check if phc index changed */
		if (!sk_get_ts_info(clock->device, &ts_info) &&
		    clock->phc_index != ts_info.phc_index) {
			clkid = posix_clock_open(clock->device, &phc_index);
			if (clkid == CLOCK_INVALID)
				return;

			posix_clock_close(clock->clkid);
			clock->clkid = clkid;
			clock->phc_index = phc_index;

			if (clock->servo) {
				servo_destroy(clock->servo);
				clock->servo = NULL;
			}

			phc_switched = 1;
		}
	}

	if (new_state == PS_MASTER || phc_switched) {
		if (clock->servo)
			servo_reset(clock->servo);
		clock->servo_state = SERVO_UNLOCKED;

		if (clock->offset_stats) {
			stats_reset(clock->offset_stats);
			stats_reset(clock->freq_stats);
			stats_reset(clock->delay_stats);
		}
	}

	pr_debug("%s: state change %s -> %s", clock->device,
		 ps_str[clock->state], ps_str[new_state]);
}

static struct clock *find_dst_clock(struct phc2sys_private *priv,
				    int phc_index)
{
	struct clock *c = NULL;
	LIST_FOREACH(c, &priv->dst_clocks, dst_list) {
		if (c->phc_index == phc_index) {
			break;
		}
	}
	return c;
}

static void reconfigure(struct phc2sys_private *priv)
{
	struct clock *c, *rt = NULL, *src = NULL, *last = NULL, *dup = NULL;
	int src_cnt = 0, dst_cnt = 0;

	pr_info("reconfiguring after port state change");
	priv->state_changed = 0;

	while (priv->dst_clocks.lh_first != NULL) {
		LIST_REMOVE(priv->dst_clocks.lh_first, dst_list);
	}

	LIST_FOREACH(c, &priv->clocks, list) {
		if (c->clkid == CLOCK_REALTIME) {
			rt = c;
			continue;
		}

		if (c->new_state) {
			clock_reinit(priv, c, c->new_state);
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
			dup = find_dst_clock(priv, c->phc_index);
			if (!dup) {
				pr_info("selecting %s for synchronization",
					c->device);
				dst_cnt++;
				LIST_INSERT_HEAD(&priv->dst_clocks,
						 c, dst_list);
			} else {
				pr_info("skipping %s: %s has the same clock "
					"and is already selected",
					c->device, dup->device);
			}
			break;
		case PS_UNCALIBRATED:
			src_cnt++;
			break;
		case PS_SLAVE:
			src = c;
			src_cnt++;
			break;
		}
		last = c;
	}
	if (src_cnt > 1) {
		pr_info("multiple master clocks available, postponing sync...");
		priv->master = NULL;
		return;
	}
	if (src_cnt > 0 && !src) {
		pr_info("master clock not ready, waiting...");
		priv->master = NULL;
		return;
	}
	if (!src_cnt && !dst_cnt) {
		pr_info("no PHC ready, waiting...");
		priv->master = NULL;
		return;
	}

	if (dst_cnt > 1 && !src) {
		if (!rt || rt->dest_only) {
			priv->master = last;
			/* Reset to original state in next reconfiguration. */
			priv->master->new_state = priv->master->state;
			priv->master->state = PS_SLAVE;
			if (rt)
				rt->state = PS_SLAVE;
			pr_info("no source, selecting %s as the default clock",
				last->device);
			return;
		}
	}

	if ((!src_cnt && (!rt || rt->dest_only)) ||
	    (!dst_cnt && !rt)) {
		pr_info("nothing to synchronize");
		priv->master = NULL;
		return;
	}
	if (!src_cnt) {
		src = rt;
		rt->state = PS_SLAVE;
	} else if (rt) {
		if (rt->state != PS_MASTER) {
			rt->state = PS_MASTER;
			clock_reinit(priv, rt, rt->state);
		}
		LIST_INSERT_HEAD(&priv->dst_clocks, rt, dst_list);
		pr_info("selecting %s for synchronization", rt->device);
	}
	priv->master = src;
	pr_info("selecting %s as the master clock", src->device);
}

static int read_phc(clockid_t clkid, clockid_t sysclk, int readings,
		    int64_t *offset, uint64_t *ts, int64_t *delay)
{
	struct timespec tdst1, tdst2, tsrc;
	int i;
	int64_t interval, best_interval = INT64_MAX;

	/* Pick the quickest clkid reading. */
	for (i = 0; i < readings; i++) {
		if (clock_gettime(sysclk, &tdst1) ||
				clock_gettime(clkid, &tsrc) ||
				clock_gettime(sysclk, &tdst2)) {
			pr_err("failed to read clock: %m");
			return 0;
		}

		interval = (tdst2.tv_sec - tdst1.tv_sec) * NS_PER_SEC +
			tdst2.tv_nsec - tdst1.tv_nsec;

		if (best_interval > interval) {
			best_interval = interval;
			*offset = (tdst1.tv_sec - tsrc.tv_sec) * NS_PER_SEC +
				tdst1.tv_nsec - tsrc.tv_nsec + interval / 2;
			*ts = tdst2.tv_sec * NS_PER_SEC + tdst2.tv_nsec;
		}
	}
	*delay = best_interval;

	return 1;
}

static int64_t get_sync_offset(struct phc2sys_private *priv, struct clock *dst)
{
	int direction = priv->forced_sync_offset;

	if (!direction)
		direction = dst->is_utc - priv->master->is_utc;
	return (int64_t)dst->sync_offset * NS_PER_SEC * direction;
}

static void update_clock_stats(struct clock *clock, unsigned int max_count,
			       int64_t offset, double freq, int64_t delay)
{
	struct stats_result offset_stats, freq_stats, delay_stats;

	stats_add_value(clock->offset_stats, offset);
	stats_add_value(clock->freq_stats, freq);
	if (delay >= 0)
		stats_add_value(clock->delay_stats, delay);

	if (stats_get_num_values(clock->offset_stats) < max_count)
		return;

	stats_get_result(clock->offset_stats, &offset_stats);
	stats_get_result(clock->freq_stats, &freq_stats);

	if (!stats_get_result(clock->delay_stats, &delay_stats)) {
		pr_info("%s "
			"rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f "
			"delay %5.0f +/- %3.0f",
			clock->device,
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev,
			delay_stats.mean, delay_stats.stddev);
	} else {
		pr_info("%s "
			"rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f",
			clock->device,
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev);
	}

	stats_reset(clock->offset_stats);
	stats_reset(clock->freq_stats);
	stats_reset(clock->delay_stats);
}

static void update_clock(struct phc2sys_private *priv, struct clock *clock,
			 int64_t offset, uint64_t ts, int64_t delay)
{
	enum servo_state state;
	double ppb;

	if (!clock->servo) {
		clock->servo = servo_add(priv, clock);
		if (!clock->servo)
			return;
	}

	if (clock_handle_leap(priv, clock, offset, ts))
		return;

	offset += get_sync_offset(priv, clock);

	if (clock->sanity_check && clockcheck_sample(clock->sanity_check, ts))
		servo_reset(clock->servo);

	ppb = servo_sample(clock->servo, offset, ts, 1.0, &state);
	clock->servo_state = state;

	switch (state) {
	case SERVO_UNLOCKED:
		break;
	case SERVO_JUMP:
		clockadj_step(clock->clkid, -offset);
		if (clock->sanity_check)
			clockcheck_step(clock->sanity_check, -offset);
		/* Fall through. */
	case SERVO_LOCKED:
	case SERVO_LOCKED_STABLE:
		clockadj_set_freq(clock->clkid, -ppb);
		if (clock->clkid == CLOCK_REALTIME)
			sysclk_set_sync();
		if (clock->sanity_check)
			clockcheck_set_freq(clock->sanity_check, -ppb);
		break;
	}

	if (clock->offset_stats) {
		update_clock_stats(clock, priv->stats_max_count, offset, ppb, delay);
	} else {
		if (delay >= 0) {
			pr_info("%s %s offset %9" PRId64 " s%d freq %+7.0f "
				"delay %6" PRId64,
				clock->device, priv->master->source_label,
				offset, state, ppb, delay);
		} else {
			pr_info("%s %s offset %9" PRId64 " s%d freq %+7.0f",
				clock->device, priv->master->source_label,
				offset, state, ppb);
		}
	}
}

static void enable_pps_output(clockid_t src)
{
	int enable = 1;

	if (!phc_has_pps(src))
		return;
	if (ioctl(CLOCKID_TO_FD(src), PTP_ENABLE_PPS, enable) < 0)
		pr_warning("failed to enable PPS output");
}

static int read_pps(int fd, int64_t *offset, uint64_t *ts)
{
	struct pps_fdata pfd;

	pfd.timeout.sec = 10;
	pfd.timeout.nsec = 0;
	pfd.timeout.flags = ~PPS_TIME_INVALID;
	if (ioctl(fd, PPS_FETCH, &pfd)) {
		pr_err("failed to fetch PPS: %m");
		return 0;
	}

	*ts = pfd.info.assert_tu.sec * NS_PER_SEC;
	*ts += pfd.info.assert_tu.nsec;

	*offset = *ts % NS_PER_SEC;
	if (*offset > NS_PER_SEC / 2)
		*offset -= NS_PER_SEC;

	return 1;
}

static int do_pps_loop(struct phc2sys_private *priv, struct clock *clock,
		       int fd)
{
	int64_t pps_offset, phc_offset, phc_delay;
	uint64_t pps_ts, phc_ts;
	clockid_t src = priv->master->clkid;

	priv->master->source_label = "pps";

	if (src == CLOCK_INVALID) {
		/* The sync offset can't be applied with PPS alone. */
		pmc_agent_set_sync_offset(priv->agent, 0);
	} else {
		enable_pps_output(priv->master->clkid);
	}

	while (is_running()) {
		if (!read_pps(fd, &pps_offset, &pps_ts)) {
			continue;
		}

		/* If a PHC is available, use it to get the whole number
		   of seconds in the offset and PPS for the rest. */
		if (src != CLOCK_INVALID) {
			if (!read_phc(src, clock->clkid, priv->phc_readings,
				      &phc_offset, &phc_ts, &phc_delay))
				return -1;

			/* Convert the time stamp to the PHC time. */
			phc_ts -= phc_offset;

			/* Check if it is close to the start of the second. */
			if (phc_ts % NS_PER_SEC > PHC_PPS_OFFSET_LIMIT) {
				pr_warning("PPS is not in sync with PHC"
					   " (0.%09lld)", phc_ts % NS_PER_SEC);
				continue;
			}

			phc_ts = phc_ts / NS_PER_SEC * NS_PER_SEC;
			pps_offset = pps_ts - phc_ts;
		}

		if (pmc_agent_update(priv->agent) < 0)
			continue;
		update_clock(priv, clock, pps_offset, pps_ts, -1);
	}
	close(fd);
	return 0;
}

static int update_needed(struct clock *c)
{
	switch (c->state) {
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_MASTER:
	case PS_PASSIVE:
		return 1;
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		break;
	}
	return 0;
}

static int do_loop(struct phc2sys_private *priv)
{
	struct timespec interval;
	struct clock *clock;
	uint64_t ts;
	int64_t offset, delay;

	interval.tv_sec = priv->phc_interval;
	interval.tv_nsec = (priv->phc_interval - interval.tv_sec) * 1e9;

	while (is_running()) {
		clock_nanosleep(CLOCK_MONOTONIC, 0, &interval, NULL);

		if (pmc_agent_update(priv->agent) < 0) {
			continue;
		}
		if (priv->state_changed) {
			/* force getting offset, as it may have
			 * changed after the port state change */
			if (pmc_agent_query_utc_offset(priv->agent, 1000)) {
				pr_err("failed to get UTC offset");
				continue;
			}
			reconfigure(priv);
		}
		if (!priv->master)
			continue;

		LIST_FOREACH(clock, &priv->dst_clocks, dst_list) {
			if (!update_needed(clock))
				continue;

			/* don't try to synchronize the clock to itself */
			if (clock->clkid == priv->master->clkid ||
			    (clock->phc_index >= 0 &&
			     clock->phc_index == priv->master->phc_index) ||
			    !strcmp(clock->device, priv->master->device))
				continue;

			if (clock->clkid == CLOCK_REALTIME &&
			    priv->master->sysoff_method >= 0) {
				/* use sysoff */
				if (sysoff_measure(CLOCKID_TO_FD(priv->master->clkid),
						   priv->master->sysoff_method,
						   priv->phc_readings,
						   &offset, &ts, &delay) < 0)
					return -1;
			} else if (priv->master->clkid == CLOCK_REALTIME &&
				   clock->sysoff_method >= 0) {
				/* use reversed sysoff */
				if (sysoff_measure(CLOCKID_TO_FD(clock->clkid),
						   clock->sysoff_method,
						   priv->phc_readings,
						   &offset, &ts, &delay) < 0)
					return -1;
				offset = -offset;
				ts += offset;
			} else {
				/* use phc */
				if (!read_phc(priv->master->clkid, clock->clkid,
					      priv->phc_readings,
					      &offset, &ts, &delay))
					continue;
			}
			update_clock(priv, clock, offset, ts, delay);
		}
	}
	return 0;
}

static int normalize_state(int state)
{
	if (state != PS_MASTER && state != PS_SLAVE &&
	    state != PS_PRE_MASTER && state != PS_UNCALIBRATED) {
		/* treat any other state as "not a master nor a slave" */
		state = PS_DISABLED;
	}
	return state;
}

static int clock_compute_state(struct phc2sys_private *priv,
			       struct clock *clock)
{
	struct port *p;
	int state = PS_DISABLED;

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

static int phc2sys_recv_subscribed(void *context, struct ptp_message *msg,
				   int excluded)
{
	struct phc2sys_private *priv = (struct phc2sys_private *) context;
	int mgt_id, state;
	struct portDS *pds;
	struct port *port;
	struct clock *clock;

	mgt_id = management_tlv_id(msg);
	if (mgt_id == excluded)
		return 0;
	switch (mgt_id) {
	case MID_PORT_DATA_SET:
		pds = management_tlv_data(msg);
		port = port_get(priv, pds->portIdentity.portNumber);
		if (!port) {
			pr_info("received data for unknown port %s",
				pid2str(&pds->portIdentity));
			return 1;
		}
		state = normalize_state(pds->portState);
		if (port->state != state) {
			pr_info("port %s changed state",
				pid2str(&pds->portIdentity));
			port->state = state;
			clock = port->clock;
			state = clock_compute_state(priv, clock);
			if (clock->state != state || clock->new_state) {
				clock->new_state = state;
				priv->state_changed = 1;
			}
		}
		return 1;
	}
	return 0;
}

static int auto_init_ports(struct phc2sys_private *priv, int add_rt)
{
	int err, number_ports, state, timestamping;
	char iface[IFNAMSIZ];
	struct clock *clock;
	struct port *port;
	unsigned int i;

	while (1) {
		if (!is_running()) {
			return -1;
		}
		err = pmc_agent_query_dds(priv->agent, 1000);
		if (!err) {
			break;
		}
		if (err == -ETIMEDOUT) {
			pr_notice("Waiting for ptp4l...");
		} else {
			return -1;
		}
	}

	number_ports = pmc_agent_get_number_ports(priv->agent);
	if (number_ports <= 0) {
		pr_err("failed to get number of ports");
		return -1;
	}

	err = pmc_agent_subscribe(priv->agent, 1000);
	if (err) {
		pr_err("failed to subscribe");
		return -1;
	}

	for (i = 1; i <= number_ports; i++) {
		err = pmc_agent_query_port_properties(priv->agent, 1000, i,
						      &state, &timestamping,
						      iface);
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
		port = port_add(priv, i, iface);
		if (!port)
			return -1;
		port->state = normalize_state(state);
	}
	if (LIST_EMPTY(&priv->clocks)) {
		pr_err("no suitable ports available");
		return -1;
	}
	LIST_FOREACH(clock, &priv->clocks, list) {
		clock->new_state = clock_compute_state(priv, clock);
	}
	priv->state_changed = 1;

	if (add_rt) {
		clock = clock_add(priv, "CLOCK_REALTIME");
		if (!clock)
			return -1;
		if (add_rt == 1)
			clock->dest_only = 1;
	}

	/* get initial offset */
	if (pmc_agent_query_utc_offset(priv->agent, 1000)) {
		pr_err("failed to get UTC offset");
		return -1;
	}
	return 0;
}

/* Returns: non-zero to skip clock update */
static int clock_handle_leap(struct phc2sys_private *priv, struct clock *clock,
			     int64_t offset, uint64_t ts)
{
	int clock_leap, node_leap = pmc_agent_get_leap(priv->agent);

	clock->sync_offset = pmc_agent_get_sync_offset(priv->agent);

	if ((node_leap || clock->leap_set) &&
	    clock->is_utc != priv->master->is_utc) {
		/* If the master clock is in UTC, get a time stamp from it, as
		   it is the clock which will include the leap second. */
		if (priv->master->is_utc) {
			struct timespec tp;
			if (clock_gettime(priv->master->clkid, &tp)) {
				pr_err("failed to read clock: %m");
				return -1;
			}
			ts = tp.tv_sec * NS_PER_SEC + tp.tv_nsec;
		}

		/* If the clock will be stepped, the time stamp has to be the
		   new time. Ignore possible 1 second error in UTC offset. */
		if (clock->is_utc && clock->servo_state == SERVO_UNLOCKED)
			ts -= offset + get_sync_offset(priv, clock);

		/* Suspend clock updates in the last second before midnight. */
		if (is_utc_ambiguous(ts)) {
			pr_info("clock update suspended due to leap second");
			return 1;
		}

		clock_leap = leap_second_status(ts, clock->leap_set,
						&node_leap,
						&clock->sync_offset);

		if (clock->leap_set != clock_leap) {
			/* Only the system clock can leap. */
			if (clock->clkid == CLOCK_REALTIME &&
			    priv->kernel_leap)
				sysclk_set_leap(clock_leap);
			else
				servo_leap(clock->servo, clock_leap);
			clock->leap_set = clock_leap;
		}
	}

	if (pmc_agent_utc_offset_traceable(priv->agent) &&
	    clock->utc_offset_set != clock->sync_offset) {
		if (clock->clkid == CLOCK_REALTIME)
			sysclk_set_tai_offset(clock->sync_offset);
		clock->utc_offset_set = clock->sync_offset;
	}

	return 0;
}

static bool hardpps_configured(int fd)
{
	return fd >= 0;
}

static int phc2sys_static_configuration(struct phc2sys_private *priv,
					const char *src_name,
					const char *dst_name)
{
	struct clock *src, *dst;

	src = clock_add(priv, src_name);
	if (!src) {
		fprintf(stderr, "valid source clock must be selected.\n");
		return -1;
	}
	src->state = PS_SLAVE;
	priv->master = src;

	dst = clock_add(priv, dst_name);
	if (!dst) {
		fprintf(stderr, "valid destination clock must be selected.\n");
		return -1;
	}
	dst->state = PS_MASTER;
	LIST_INSERT_HEAD(&priv->dst_clocks, dst, dst_list);

	return 0;
}

static bool phc2sys_using_systemclock(struct phc2sys_private *priv)
{
	struct clock *c;

	LIST_FOREACH(c, &priv->clocks, list) {
		if (c->clkid == CLOCK_REALTIME) {
			return true;
		}
	}
	return false;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\n"
		"usage: %s [options]\n\n"
		"\n"
		" automatic configuration:\n"
		" -a             turn on autoconfiguration\n"
		" -r             synchronize system (realtime) clock\n"
		"                repeat -r to consider it also as a time source\n"
		" manual configuration:\n"
		" -c [dev|name]  time sink device (CLOCK_REALTIME)\n"
		" -d [dev]       time source PPS device\n"
		" -s [dev|name]  time source device\n"
		" -O [offset]    sink-source time offset in seconds (0)\n"
		" -w             wait for ptp4l\n"
		" common options:\n"
		" -f [file]      configuration file\n"
		" -E [pi|linreg] clock servo (pi)\n"
		" -P [kp]        proportional constant (0.7)\n"
		" -I [ki]        integration constant (0.3)\n"
		" -S [step]      step threshold (disabled)\n"
		" -F [step]      step threshold only on start (0.00002)\n"
		" -R [rate]      update rate for the time sink devices in HZ (1.0)\n"
		" -N [num]       number of source clock readings per update (5)\n"
		" -L [limit]     sanity frequency limit in ppb (200000000)\n"
		" -M [num]       NTP SHM segment number (0)\n"
		" -u [num]       number of clock updates in summary stats (0)\n"
		" -n [num]       domain number (0)\n"
		" -x             apply leap seconds by servo instead of kernel\n"
		" -z [path]      server address for UDS (/var/run/ptp4l)\n"
		" -l [num]       set the logging level to 'num' (6)\n"
		" -t [tag]       add tag to log messages\n"
		" -m             print messages to stdout\n"
		" -q             do not print messages to the syslog\n"
		" -v             prints the software version and exits\n"
		" -h             prints this message and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *config = NULL, *dst_name = NULL, *progname, *src_name = NULL;
	char uds_local[MAX_IFNAME_SIZE + 1];
	int autocfg = 0, c, domain_number = 0, index, ntpshm_segment, offset;
	int pps_fd = -1, print_level = LOG_INFO, r = -1, rt = 0;
	int wait_sync = 0;
	struct config *cfg;
	struct option *opts;
	double phc_rate, tmp;
	struct phc2sys_private priv = {
		.phc_readings = 5,
		.phc_interval = 1.0,
	};

	handle_term_signals();

	cfg = phc2sys_config = config_create();
	if (!cfg) {
		return -1;
	}
	priv.agent = pmc_agent_create();
	if (!priv.agent) {
		return -1;
	}

	opts = config_long_options(cfg);

	config_set_double(cfg, "pi_proportional_const", KP);
	config_set_double(cfg, "pi_integral_const", KI);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv,
				"arc:d:f:s:E:P:I:S:F:R:N:O:L:M:i:u:wn:xz:l:t:mqvh",
				opts, &index))) {
		switch (c) {
		case 0:
			if (config_parse_option(cfg, opts[index].name, optarg)) {
				goto bad_usage;
			}
			break;
		case 'a':
			autocfg = 1;
			break;
		case 'r':
			rt++;
			break;
		case 'c':
			dst_name = optarg;
			break;
		case 'd':
			pps_fd = open(optarg, O_RDONLY);
			if (pps_fd < 0) {
				fprintf(stderr,
					"cannot open '%s': %m\n", optarg);
				goto end;
			}
			break;
		case 'f':
			config = optarg;
			break;
		case 'i':
			fprintf(stderr,
				"'-i' has been deprecated. please use '-s' instead.\n");
            /* fallthrough */
		case 's':
			src_name = optarg;
			break;
		case 'E':
			if (!strcasecmp(optarg, "pi")) {
				config_set_int(cfg, "clock_servo",
					       CLOCK_SERVO_PI);
			} else if (!strcasecmp(optarg, "linreg")) {
				config_set_int(cfg, "clock_servo",
					       CLOCK_SERVO_LINREG);
			} else if (!strcasecmp(optarg, "ntpshm")) {
				config_set_int(cfg, "clock_servo",
					       CLOCK_SERVO_NTPSHM);
			} else {
				fprintf(stderr,
					"invalid servo name %s\n", optarg);
				goto end;
			}
			break;
		case 'P':
			if (get_arg_val_d(c, optarg, &tmp, 0.0, DBL_MAX) ||
			    config_set_double(cfg, "pi_proportional_const", tmp))
				goto end;
			break;
		case 'I':
			if (get_arg_val_d(c, optarg, &tmp, 0.0, DBL_MAX) ||
			    config_set_double(cfg, "pi_integral_const", tmp))
				goto end;
			break;
		case 'S':
			if (get_arg_val_d(c, optarg, &tmp, 0.0, DBL_MAX) ||
			    config_set_double(cfg, "step_threshold", tmp))
				goto end;
			break;
		case 'F':
			if (get_arg_val_d(c, optarg, &tmp, 0.0, DBL_MAX) ||
			    config_set_double(cfg, "first_step_threshold", tmp))
				goto end;
			break;
		case 'R':
			if (get_arg_val_d(c, optarg, &phc_rate, 1e-9, DBL_MAX))
				goto end;
			priv.phc_interval = 1.0 / phc_rate;
			break;
		case 'N':
			if (get_arg_val_i(c, optarg, &priv.phc_readings, 1, INT_MAX))
				goto end;
			break;
		case 'O':
			if (get_arg_val_i(c, optarg, &offset, INT_MIN, INT_MAX)) {
				goto end;
			}
			pmc_agent_set_sync_offset(priv.agent, offset);
			priv.forced_sync_offset = -1;
			break;
		case 'L':
			if (get_arg_val_i(c, optarg, &priv.sanity_freq_limit, 0, INT_MAX) ||
			    config_set_int(cfg, "sanity_freq_limit", priv.sanity_freq_limit)) {
				goto end;
			}
			break;
		case 'M':
			if (get_arg_val_i(c, optarg, &ntpshm_segment, INT_MIN, INT_MAX) ||
			    config_set_int(cfg, "ntpshm_segment", ntpshm_segment))
				goto end;
			break;
		case 'u':
			if (get_arg_val_ui(c, optarg, &priv.stats_max_count,
					  0, UINT_MAX))
				goto end;
			break;
		case 'w':
			wait_sync = 1;
			break;
		case 'n':
			if (get_arg_val_i(c, optarg, &domain_number, 0, 255) ||
			    config_set_int(cfg, "domainNumber", domain_number)) {
				goto end;
			}
			break;
		case 'x':
			if (config_set_int(cfg, "kernel_leap", 0)) {
				goto end;
			}
			break;
		case 'z':
			if (strlen(optarg) > MAX_IFNAME_SIZE) {
				fprintf(stderr, "path %s too long, max is %d\n",
					optarg, MAX_IFNAME_SIZE);
				goto end;
			}
			if (config_set_string(cfg, "uds_address", optarg)) {
				goto end;
			}
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX) ||
			    config_set_int(cfg, "logging_level", print_level)) {
				goto end;
			}
			break;
		case 't':
			if (config_set_string(cfg, "message_tag", optarg)) {
				goto end;
			}
			break;
		case 'm':
			if (config_set_int(cfg, "verbose", 1)) {
				goto end;
			}
			break;
		case 'q':
			if (config_set_int(cfg, "use_syslog", 0)) {
				goto end;
			}
			break;
		case 'v':
			version_show(stdout);
			config_destroy(cfg);
			return 0;
		case 'h':
			usage(progname);
			config_destroy(cfg);
			return 0;
		default:
			goto bad_usage;
		}
	}

	if (config && (c = config_read(config, cfg))) {
		return c;
	}

	if (autocfg && (src_name || dst_name || hardpps_configured(pps_fd) ||
			wait_sync || priv.forced_sync_offset)) {
		fprintf(stderr,
			"autoconfiguration cannot be mixed with manual config options.\n");
		goto bad_usage;
	}
	if (!autocfg && !hardpps_configured(pps_fd) && !src_name) {
		fprintf(stderr,
			"autoconfiguration or valid source clock must be selected.\n");
		goto bad_usage;
	}

	if (!autocfg && !wait_sync && !priv.forced_sync_offset) {
		fprintf(stderr,
			"time offset must be specified using -w or -O\n");
		goto bad_usage;
	}

	if (!dst_name) {
		dst_name = "CLOCK_REALTIME";
	}
	if (hardpps_configured(pps_fd) && strcmp(dst_name, "CLOCK_REALTIME")) {
		fprintf(stderr,
			"cannot use a pps device unless destination is CLOCK_REALTIME\n");
		goto bad_usage;
	}

	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	priv.servo_type = config_get_int(cfg, NULL, "clock_servo");
	if (priv.servo_type == CLOCK_SERVO_NTPSHM) {
		config_set_int(cfg, "kernel_leap", 0);
		config_set_int(cfg, "sanity_freq_limit", 0);
	}
	priv.kernel_leap = config_get_int(cfg, NULL, "kernel_leap");
	priv.sanity_freq_limit = config_get_int(cfg, NULL, "sanity_freq_limit");

	snprintf(uds_local, sizeof(uds_local), "/var/run/phc2sys.%d",
		 getpid());

	if (autocfg) {
		if (init_pmc_node(cfg, priv.agent, uds_local,
				  phc2sys_recv_subscribed, &priv))
			goto end;
		if (auto_init_ports(&priv, rt) < 0)
			goto end;
		r = do_loop(&priv);
		goto end;
	}

	r = phc2sys_static_configuration(&priv, src_name, dst_name);
	if (r) {
		goto end;
	}

	r = -1;

	if (wait_sync) {
		if (init_pmc_node(cfg, priv.agent, uds_local,
				  phc2sys_recv_subscribed, &priv))
			goto end;

		while (is_running()) {
			r = run_pmc_wait_sync(priv.agent, 1000);
			if (r < 0)
				goto end;
			if (r > 0)
				break;
			else
				pr_notice("Waiting for ptp4l...");
		}

		if (!priv.forced_sync_offset) {
			r = pmc_agent_query_utc_offset(priv.agent, 1000);
			if (r) {
				pr_err("failed to get UTC offset");
				goto end;
			}
		}

		if (priv.forced_sync_offset ||
		    !phc2sys_using_systemclock(&priv) ||
		    hardpps_configured(pps_fd)) {
			pmc_agent_disable(priv.agent);
		}
	}

	if (hardpps_configured(pps_fd)) {
		struct clock *dst = LIST_FIRST(&priv.dst_clocks);

		/* only one destination clock allowed with PPS until we
		 * implement a mean to specify PTP port to PPS mapping */
		dst->servo = servo_add(&priv, dst);
		servo_sync_interval(dst->servo, 1.0);
		r = do_pps_loop(&priv, dst, pps_fd);
	} else {
		r = do_loop(&priv);
	}

end:
	pmc_agent_destroy(priv.agent);
	clock_cleanup(&priv);
	port_cleanup(&priv);
	config_destroy(cfg);
	msg_cleanup();
	return r;
bad_usage:
	usage(progname);
	config_destroy(cfg);
	return -1;
}
