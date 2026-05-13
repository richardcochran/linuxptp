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
#include "sad.h"
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

#define MAX_DST_CLOCKS 128

#define MAX_DOMAINS 16

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
	int static_state;
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

struct domain {
	unsigned int stats_max_count;
	int sanity_freq_limit;
	enum servo_type servo_type;
	int phc_readings;
	double phc_interval;
	int forced_sync_offset;
	int kernel_leap;
	int state_changed;
	int free_running;
	int has_rt_clock;
	struct pmc_agent *agent;
	int agent_subscribed;
	LIST_HEAD(port_head, port) ports;
	LIST_HEAD(clock_head, clock) clocks;
	LIST_HEAD(dst_clock_head, clock) dst_clocks;
	struct clock *src_clock;
	struct domain *src_domain;
	int src_priority;
};

static struct config *phc2sys_config;

static int clock_handle_leap(struct domain *domain,
			     struct clock *clock,
			     int64_t offset, uint64_t ts);

static struct servo *servo_add(struct domain *domain,
			       struct clock *clock)
{
	double ppb;
	int max_ppb;
	struct servo *servo;

	clockadj_init(clock->clkid);
	ppb = clockadj_get_freq(clock->clkid);
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

	servo = servo_create(phc2sys_config, domain->servo_type,
			     -ppb, max_ppb, 0);
	if (!servo) {
		pr_err("Failed to create servo");
		return NULL;
	}

	servo_sync_interval(servo, domain->phc_interval);

	return servo;
}

static struct clock *clock_add(struct domain *domain, const char *device,
			       int phc_index)
{
	struct clock *c, *c2;
	clockid_t clkid = CLOCK_INVALID;
	char phc_device[19];

	if (device) {
		if (phc_index >= 0) {
			snprintf(phc_device, sizeof(phc_device), "/dev/ptp%d",
				 phc_index);
			clkid = posix_clock_open(phc_device, &phc_index);
		} else {
			clkid = posix_clock_open(device, &phc_index);
		}
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

	if (domain->stats_max_count > 0) {
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
	if (domain->sanity_freq_limit) {
		c->sanity_check = clockcheck_create(domain->sanity_freq_limit);
		if (!c->sanity_check) {
			pr_err("failed to create clock check");
			return NULL;
		}
	}

	if (clkid != CLOCK_INVALID && clkid != CLOCK_REALTIME)
		c->sysoff_method = sysoff_probe(CLOCKID_TO_FD(clkid),
						CLOCK_REALTIME,
						domain->phc_readings);

	/* Add the clock to the end of the list to keep them in the
	   command-line or ptp4l order */
	if (LIST_EMPTY(&domain->clocks)) {
		LIST_INSERT_HEAD(&domain->clocks, c, list);
	} else {
		LIST_FOREACH(c2, &domain->clocks, list) {
			if (LIST_NEXT(c2, list))
				continue;
			LIST_INSERT_AFTER(c2, c, list);
			break;
		}
	}

	return c;
}

static void clock_cleanup(struct domain *domain)
{
	struct clock *c, *tmp;

	LIST_FOREACH_SAFE(c, &domain->clocks, list, tmp) {
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

static void port_cleanup(struct domain *domain)
{
	struct port *p, *tmp;

	LIST_FOREACH_SAFE(p, &domain->ports, list, tmp) {
		free(p);
	}
}

static struct port *port_get(struct domain *domain, unsigned int number)
{
	struct port *p;

	LIST_FOREACH(p, &domain->ports, list) {
		if (p->number == number)
			return p;
	}
	return NULL;
}

static struct port *port_add(struct domain *domain, unsigned int number,
			     char *device, int phc_index)
{
	struct port *p;
	struct clock *c = NULL, *tmp;

	p = port_get(domain, number);
	if (p)
		return p;
	/* port is a new one, look whether we have the device already on
	 * a different port */
	LIST_FOREACH(tmp, &domain->clocks, list) {
		if (!strcmp(tmp->device, device)) {
			c = tmp;
			break;
		}
	}
	if (!c) {
		c = clock_add(domain, device, phc_index);
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
	LIST_INSERT_HEAD(&domain->ports, p, list);
	return p;
}

static void clock_reinit(struct domain *domain, struct clock *clock,
			 int new_state)
{
	int err = -1, phc_index = -1, phc_switched = 0, timestamping;
	char iface[IFNAMSIZ], phc_device[19];
	enum port_state state;
	struct port *p;
	clockid_t clkid = CLOCK_INVALID;

	LIST_FOREACH(p, &domain->ports, list) {
		if (p->clock != clock) {
			continue;
		}
		err = pmc_agent_query_port_properties(domain->agent, 1000,
						      p->number, &state,
						      &timestamping, &phc_index,
						      iface);
		if (!err) {
			p->state = port_state_normalize(state);
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
		if (clock->phc_index != phc_index) {
			snprintf(phc_device, sizeof(phc_device), "/dev/ptp%d",
				 phc_index);
			clkid = posix_clock_open(phc_device, &phc_index);
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

static struct clock *find_dst_clock(struct domain *domain,
				    int phc_index)
{
	struct clock *c = NULL;
	LIST_FOREACH(c, &domain->dst_clocks, dst_list) {
		if (c->phc_index == phc_index) {
			break;
		}
	}
	return c;
}

static struct clock *find_nonstatic_clock(struct domain *domain,
					  int phc_index)
{
	struct clock *c = NULL;
	LIST_FOREACH(c, &domain->clocks, list) {
		if (!c->static_state && c->phc_index == phc_index) {
			break;
		}
	}
	return c;
}

static int reconfigure_domain(struct domain *domain)
{
	struct clock *c, *src = NULL, *dup = NULL;
	int src_cnt = 0, dst_cnt = 0;

	domain->state_changed = 0;
	domain->src_domain = domain;

	while (domain->dst_clocks.lh_first != NULL) {
		LIST_REMOVE(LIST_FIRST(&domain->dst_clocks), dst_list);
	}

	if (!domain->has_rt_clock && !domain->agent_subscribed) {
		domain->src_clock = NULL;
		return 0;
	}

	LIST_FOREACH(c, &domain->clocks, list) {
		if (c->clkid == CLOCK_REALTIME) {
			/* If present, it can always be a sink clock */
			LIST_INSERT_HEAD(&domain->dst_clocks, c, dst_list);
			domain->src_clock = c->dest_only ? NULL : c;
			return 0;
		}

		if (c->new_state) {
			clock_reinit(domain, c, c->new_state);
			c->state = c->new_state;
			c->new_state = 0;
		}

		/* Ignore the clock if its state is not following ptp4l and has
		   the same PHC index as a clock that is following ptp4l */
		if (c->static_state) {
			dup = find_nonstatic_clock(domain, c->phc_index);
			if (dup) {
				pr_info("skipping static %s: %s has the same clock",
					c->device, dup->device);
				continue;
			}
		}

		switch (c->state) {
		case PS_FAULTY:
		case PS_DISABLED:
		case PS_LISTENING:
		case PS_PRE_MASTER:
		case PS_MASTER:
		case PS_PASSIVE:
			dup = find_dst_clock(domain, c->phc_index);
			if (!dup) {
				pr_info("selecting %s for synchronization",
					c->device);
				dst_cnt++;
				LIST_INSERT_HEAD(&domain->dst_clocks,
						 c, dst_list);
				if (c->sanity_check)
					clockcheck_reset(c->sanity_check);
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
	}
	if (src_cnt > 1) {
		pr_info("multiple source clocks available, postponing sync...");
		domain->src_clock = NULL;
		return -1;
	}
	if (src_cnt > 0 && !src) {
		pr_info("source clock not ready, waiting...");
		domain->src_clock = NULL;
		return -1;
	}
	if (!src_cnt && !dst_cnt) {
		pr_info("no PHC ready, waiting...");
		domain->src_clock = NULL;
		return -1;
	}

	if (!src) {
		domain->src_clock = NULL;
		return 0;
	}

	domain->src_clock = src;
	pr_info("selecting %s as domain source clock", src->device);
	return 0;
}

static int compare_domains(struct domain *a, struct domain *b)
{
	if (!a || !b) {
		if (a && a->src_clock)
			return -1;
		if (b && b->src_clock)
			return 1;
		return 0;
	}

	if (!a->src_clock != !b->src_clock)
		return !!b->src_clock - !!a->src_clock;

	return b->src_priority - a->src_priority;
}

static void reconfigure(struct domain *domains, int n_domains)
{
	struct domain *src_domain = NULL, *rt_domain = NULL;
	int i;

	pr_info("reconfiguring after port state change");

	for (i = 0; i < n_domains; i++) {
		while (!LIST_EMPTY(&domains[i].dst_clocks))
			LIST_REMOVE(LIST_FIRST(&domains[i].dst_clocks), dst_list);

		if (reconfigure_domain(&domains[i]))
			return;

		if (compare_domains(src_domain, &domains[i]) > 0) {
			src_domain = &domains[i];
		}

		if (domains[i].has_rt_clock)
			rt_domain = &domains[i];
	}

	if (n_domains <= 1 || !src_domain) {
		return;
	}

	if (rt_domain && src_domain != rt_domain) {
		pr_info("selecting CLOCK_REALTIME for synchronization");
	}
	if (src_domain == rt_domain) {
		pr_info("selecting CLOCK_REALTIME as source clock");
	} else if (n_domains - !!rt_domain > 1) {
		pr_info("selecting %s as out-of-domain source clock",
			src_domain->src_clock->device);
	}

	for (i = 0; i < n_domains; i++) {
		if (domains[i].src_clock && domains[i].src_priority > 0)
			continue;
		domains[i].src_clock = src_domain->src_clock;
		domains[i].src_domain = src_domain;
	}
}

static int64_t get_sync_offset(struct domain *domain, struct clock *dst)
{
	int direction = domain->forced_sync_offset;

	if (!direction)
		direction = dst->is_utc - domain->src_clock->is_utc;
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

static void update_clock(struct domain *domain, struct clock *clock,
			 int64_t offset, uint64_t ts, int64_t delay)
{
	enum servo_state state = SERVO_UNLOCKED;
	double ppb = 0.0;

	if (!clock->servo) {
		clock->servo = servo_add(domain, clock);
		if (!clock->servo)
			return;
	}

	if (clock_handle_leap(domain, clock, offset, ts))
		return;

	offset += get_sync_offset(domain, clock);

	if (domain->free_running)
		goto report;

	if (clock->sanity_check && clockcheck_sample(clock->sanity_check, ts))
		servo_reset(clock->servo);

	ppb = servo_sample(clock->servo, offset, ts, 1.0, &state);
	clock->servo_state = state;

	switch (state) {
	case SERVO_UNLOCKED:
		break;
	case SERVO_JUMP:
		if (clockadj_step(clock->clkid, -offset)) {
			goto servo_unlock;
		}
		if (clock->sanity_check)
			clockcheck_step(clock->sanity_check, -offset);
		/* Fall through. */
	case SERVO_LOCKED:
	case SERVO_LOCKED_STABLE:
		if (clock->sanity_check)
			clockcheck_freq(clock->sanity_check,
					clockadj_get_freq(clock->clkid));
		if (clockadj_set_freq(clock->clkid, -ppb)) {
			goto servo_unlock;
		}
		if (clock->clkid == CLOCK_REALTIME)
			sysclk_set_sync();
		if (clock->sanity_check)
			clockcheck_set_freq(clock->sanity_check, -ppb);
		break;
	}

report:
	if (clock->offset_stats) {
		update_clock_stats(clock, domain->stats_max_count, offset, ppb, delay);
	} else {
		if (delay >= 0) {
			pr_info("%s %s offset %9" PRId64 " s%d freq %+7.0f "
				"delay %6" PRId64,
				clock->device, domain->src_clock->source_label,
				offset, state, ppb, delay);
		} else {
			pr_info("%s %s offset %9" PRId64 " s%d freq %+7.0f",
				clock->device, domain->src_clock->source_label,
				offset, state, ppb);
		}
	}
	return;

servo_unlock:
	servo_reset(clock->servo);
	clock->servo_state = SERVO_UNLOCKED;
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

static int do_pps_loop(struct domain *domain, struct clock *clock,
		       int fd)
{
	int64_t pps_offset, phc_offset, phc_delay;
	uint64_t pps_ts, phc_ts;
	clockid_t src = domain->src_clock->clkid;
	int err;

	domain->src_clock->source_label = "pps";

	if (src == CLOCK_INVALID) {
		/* The sync offset can't be applied with PPS alone. */
		pmc_agent_set_sync_offset(domain->agent, 0);
	} else {
		enable_pps_output(domain->src_clock->clkid);
	}

	while (is_running()) {
		if (!read_pps(fd, &pps_offset, &pps_ts)) {
			continue;
		}

		/* If a PHC is available, use it to get the whole number
		   of seconds in the offset and PPS for the rest. */
		if (src != CLOCK_INVALID) {
			err = clockadj_compare(src, clock->clkid,
					       domain->phc_readings,
					       &phc_offset, &phc_ts,
					       &phc_delay);
			if (err == -EBUSY)
				continue;
			if (err)
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

		if (pmc_agent_update(domain->agent) < 0)
			continue;
		update_clock(domain, clock, pps_offset, pps_ts, -1);
	}
	close(fd);
	return 0;
}

static int update_needed(struct clock *c)
{
	if (c->clkid == CLOCK_REALTIME)
		return 1;

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

static int update_domain_clocks(struct domain *domain)
{
	int64_t offset, delay;
	struct clock *clock;
	uint64_t ts;
	int err;

	LIST_FOREACH(clock, &domain->dst_clocks, dst_list) {
		if (!update_needed(clock))
			continue;

		/* don't try to synchronize the clock to itself */
		if (clock->clkid == domain->src_clock->clkid ||
		    (clock->phc_index >= 0 &&
		     clock->phc_index == domain->src_clock->phc_index) ||
		    !strcmp(clock->device, domain->src_clock->device))
			continue;

		if (clock->clkid == CLOCK_REALTIME &&
		    domain->src_clock->sysoff_method >= 0) {
			/* use sysoff */
			err = sysoff_measure(CLOCKID_TO_FD(domain->src_clock->clkid),
					     CLOCK_REALTIME,
					     domain->src_clock->sysoff_method,
					     domain->phc_readings,
					     &offset, &ts, &delay);
		} else if (domain->src_clock->clkid == CLOCK_REALTIME &&
			   clock->sysoff_method >= 0) {
			/* use reversed sysoff */
			err = sysoff_measure(CLOCKID_TO_FD(clock->clkid),
					     CLOCK_REALTIME,
					     clock->sysoff_method,
					     domain->phc_readings,
					     &offset, &ts, &delay);
			if (!err) {
				offset = -offset;
				ts += offset;
			}
		} else {
			/* use phc */
			err = clockadj_compare(domain->src_clock->clkid,
					       clock->clkid,
					       domain->phc_readings,
					       &offset, &ts, &delay);
		}
		if (err == -EBUSY)
			continue;
		if (err)
			return -1;
		update_clock(domain, clock, offset, ts, delay);
	}

	return 0;
}

static int do_loop(struct domain *domains, int n_domains)
{
	int i, state_changed, prev_sub;
	struct timespec interval;
	struct domain *domain;

	/* All domains have the same interval */
	interval.tv_sec = domains[0].phc_interval;
	interval.tv_nsec = (domains[0].phc_interval - interval.tv_sec) * 1e9;

	while (is_running()) {
		clock_nanosleep(CLOCK_MONOTONIC, 0, &interval, NULL);

		state_changed = 0;
		for (i = 0; i < n_domains; i++) {
			domain = &domains[i];
			if (pmc_agent_update(domain->agent) < 0) {
				continue;
			}

			prev_sub = domain->agent_subscribed;
			domain->agent_subscribed =
				pmc_agent_is_subscribed(domain->agent);
			if (!domain->has_rt_clock && !domain->agent_subscribed) {
				if (prev_sub) {
					pr_err("Lost connection to ptp4l #%d", i + 1);
					state_changed = 1;
				}
				continue;
			}

			if (domain->state_changed) {
				state_changed = 1;

				/* force getting offset, as it may have
				 * changed after the port state change */
				if (pmc_agent_query_utc_offset(domain->agent,
							       1000)) {
					pr_err("failed to get UTC offset");
					continue;
				}
			}
		}

		if (state_changed) {
			reconfigure(domains, n_domains);
			state_changed = 0;
		}

		for (i = 0; i < n_domains; i++) {
			domain = &domains[i];

			if (!domain->src_clock)
				continue;

			if (update_domain_clocks(domain))
				return -1;
		}
	}
	return 0;
}

static int clock_compute_state(struct domain *domain,
			       struct clock *clock)
{
	struct port *p;
	int state = PS_DISABLED;

	LIST_FOREACH(p, &domain->ports, list) {
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
	struct domain *domain = (struct domain *) context;
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
		port = port_get(domain, pds->portIdentity.portNumber);
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
			state = clock_compute_state(domain, clock);
			if (clock->state != state || clock->new_state) {
				clock->new_state = state;
				domain->state_changed = 1;
			}
		}
		return 1;
	}
	return 0;
}

static int auto_init_ports(struct domain *domain)
{
	int err, number_ports, phc_index, timestamping;
	enum port_state state;
	char iface[IFNAMSIZ];
	struct clock *clock;
	struct port *port;
	unsigned int i;

	while (1) {
		if (!is_running()) {
			return -1;
		}
		err = pmc_agent_query_dds(domain->agent, 1000);
		if (!err) {
			break;
		}
		if (err == -ETIMEDOUT) {
			pr_notice("Waiting for ptp4l...");
		} else {
			return -1;
		}
	}

	number_ports = pmc_agent_get_number_ports(domain->agent);
	if (number_ports <= 0) {
		pr_err("failed to get number of ports");
		return -1;
	}

	err = pmc_agent_subscribe(domain->agent, 1000, domain->phc_interval);
	if (err) {
		pr_err("failed to subscribe");
		return -1;
	}

	while (!pmc_agent_is_subscribed(domain->agent)) {
		usleep(10000);
		if (pmc_agent_update(domain->agent) < 0)
			return -1;
	}

	for (i = 1; i <= number_ports; i++) {
		err = pmc_agent_query_port_properties(domain->agent, 1000, i,
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
		port = port_add(domain, i, iface, phc_index);
		if (!port)
			return -1;
		port->state = port_state_normalize(state);
	}

	if (LIST_EMPTY(&domain->clocks)) {
		pr_err("no suitable ports available");
		return -1;
	}
	LIST_FOREACH(clock, &domain->clocks, list) {
		clock->new_state = clock_compute_state(domain, clock);
	}
	domain->state_changed = 1;
	domain->src_priority = 1;

	/* get initial offset */
	if (pmc_agent_query_utc_offset(domain->agent, 1000)) {
		pr_err("failed to get UTC offset");
		return -1;
	}
	return 0;
}

static int auto_init_rt(struct domain *domain, int dest_only)
{
	struct clock *clock;

	clock = clock_add(domain, "CLOCK_REALTIME", -1);
	if (!clock)
		return -1;
	clock->dest_only = dest_only;
	domain->src_priority = 0;
	domain->has_rt_clock = 1;
	return 0;
}

/* Returns: non-zero to skip clock update */
static int clock_handle_leap(struct domain *domain, struct clock *clock,
			     int64_t offset, uint64_t ts)
{
	int clock_leap, node_leap;
	struct pmc_agent *agent;

	/* The system clock's domain doesn't have a subscribed agent */
	agent = domain->has_rt_clock ? domain->src_domain->agent : domain->agent;

	node_leap = pmc_agent_get_leap(agent);
	clock->sync_offset = pmc_agent_get_sync_offset(agent);

	if ((node_leap || clock->leap_set) &&
	    clock->is_utc != domain->src_clock->is_utc) {
		/* If the source clock is in UTC, get a time stamp from it, as
		   it is the clock which will include the leap second. */
		if (domain->src_clock->is_utc) {
			struct timespec tp;
			if (clock_gettime(domain->src_clock->clkid, &tp)) {
				pr_err("failed to read clock: %m");
				return -1;
			}
			ts = tp.tv_sec * NS_PER_SEC + tp.tv_nsec;
		}

		/* If the clock will be stepped, the time stamp has to be the
		   new time. Ignore possible 1 second error in UTC offset. */
		if (clock->is_utc && clock->servo_state == SERVO_UNLOCKED)
			ts -= offset + get_sync_offset(domain, clock);

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
			    domain->kernel_leap)
				sysclk_set_leap(clock_leap);
			else
				servo_leap(clock->servo, clock_leap);
			clock->leap_set = clock_leap;
		}
	}

	if (pmc_agent_utc_offset_traceable(agent) &&
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

static int phc2sys_static_src_configuration(struct domain *domain,
					    const char *src_name)
{
	struct clock *src;

	src = clock_add(domain, src_name, -1);
	if (!src) {
		fprintf(stderr, "valid source clock must be selected.\n");
		return -1;
	}
	src->state = PS_SLAVE;
	domain->src_clock = src;
	domain->src_domain = domain;

	return 0;
}

static int phc2sys_static_dst_configuration(struct domain *domain,
					    const char *dst_name)
{
	struct clock *dst;

	dst = clock_add(domain, dst_name, -1);
	if (!dst) {
		fprintf(stderr, "valid destination clock must be selected.\n");
		return -1;
	}
	dst->state = PS_MASTER;
	dst->static_state = 1;
	LIST_INSERT_HEAD(&domain->dst_clocks, dst, dst_list);

	return 0;
}

static bool phc2sys_using_systemclock(struct domain *domain)
{
	struct clock *c;

	LIST_FOREACH(c, &domain->clocks, list) {
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
		" -z [path]      server address for UDS (/var/run/ptp/ptp4l)\n"
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
	char *config = NULL, *progname, *src_name = NULL;
	const char *dst_names[MAX_DST_CLOCKS], *uds_remotes[MAX_DOMAINS];
	char uds_local[MAX_IFNAME_SIZE + 1];
	int domain_numbers[MAX_DOMAINS], domain_number_cnt = 0;
	int i, autocfg = 0, c, index, ntpshm_segment, offset = 0;
	int pps_fd = -1, cmd_line_print_level, r = -1, rt = 0;
	int wait_sync = 0, dst_cnt = 0, uds_remote_cnt = 0;
	struct config *cfg;
	struct option *opts;
	double phc_rate, tmp;
	struct domain domains[MAX_DOMAINS];
	struct domain settings = {
		.phc_readings = 5,
		.phc_interval = 1.0,
	};
	int n_domains = 0;

	memset(domains, 0, sizeof (domains));

	handle_term_signals();

	cfg = phc2sys_config = config_create();
	if (!cfg) {
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
			if (dst_cnt == MAX_DST_CLOCKS) {
				fprintf(stderr, "too many sink clocks\n");
				goto bad_usage;
			}
			dst_names[dst_cnt++] = optarg;
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
			} else if (!strcasecmp(optarg, "refclock_sock")) {
				config_set_int(cfg, "clock_servo",
					       CLOCK_SERVO_REFCLOCK_SOCK);
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
			settings.phc_interval = 1.0 / phc_rate;
			break;
		case 'N':
			if (get_arg_val_i(c, optarg, &settings.phc_readings, 1, INT_MAX))
				goto end;
			break;
		case 'O':
			if (get_arg_val_i(c, optarg, &offset, INT_MIN, INT_MAX)) {
				goto end;
			}
			settings.forced_sync_offset = -1;
			break;
		case 'L':
			if (get_arg_val_i(c, optarg, &settings.sanity_freq_limit, 0, INT_MAX) ||
			    config_set_int(cfg, "sanity_freq_limit", settings.sanity_freq_limit)) {
				goto end;
			}
			break;
		case 'M':
			if (get_arg_val_i(c, optarg, &ntpshm_segment, INT_MIN, INT_MAX) ||
			    config_set_int(cfg, "ntpshm_segment", ntpshm_segment))
				goto end;
			break;
		case 'u':
			if (get_arg_val_ui(c, optarg, &settings.stats_max_count,
					  0, UINT_MAX))
				goto end;
			break;
		case 'w':
			wait_sync = 1;
			break;
		case 'n':
			if (domain_number_cnt == MAX_DOMAINS) {
				fprintf(stderr, "too many domains\n");
				goto end;
			}
			if (get_arg_val_i(c, optarg,
					  &domain_numbers[domain_number_cnt++],
					  0, 255)) {
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
			if (uds_remote_cnt == MAX_DOMAINS) {
				fprintf(stderr, "too many domains\n");
				goto end;
			}
			uds_remotes[uds_remote_cnt++] = optarg;
			n_domains++;
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &cmd_line_print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX) ||
			    config_set_int(cfg, "logging_level", cmd_line_print_level)) {
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

	if (!autocfg && dst_cnt == 0) {
		dst_names[dst_cnt++] = "CLOCK_REALTIME";
	}

	if (autocfg && (src_name || hardpps_configured(pps_fd) ||
			wait_sync || settings.forced_sync_offset)) {
		fprintf(stderr,
			"autoconfiguration cannot be mixed with manual config options.\n");
		goto bad_usage;
	}
	if (!autocfg && n_domains > 1) {
		fprintf(stderr,
			"autoconfiguration needed with multiple domains.\n");
		goto bad_usage;
	}

	if (!autocfg && !hardpps_configured(pps_fd) && !src_name) {
		fprintf(stderr,
			"autoconfiguration or valid source clock must be selected.\n");
		goto bad_usage;
	}

	if (hardpps_configured(pps_fd) && (dst_cnt != 1 ||
	    strcmp(dst_names[0], "CLOCK_REALTIME"))) {
		fprintf(stderr,
			"cannot use a pps device unless destination is CLOCK_REALTIME\n");
		goto bad_usage;
	}

	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	settings.free_running = config_get_int(cfg, NULL, "free_running");
	settings.servo_type = config_get_int(cfg, NULL, "clock_servo");
	if (settings.free_running || settings.servo_type == CLOCK_SERVO_NTPSHM) {
		config_set_int(cfg, "kernel_leap", 0);
		config_set_int(cfg, "sanity_freq_limit", 0);
	}
	settings.kernel_leap = config_get_int(cfg, NULL, "kernel_leap");
	settings.sanity_freq_limit = config_get_int(cfg, NULL, "sanity_freq_limit");

	if (autocfg) {
		if (n_domains == 0)
			n_domains = 1;
		if (rt)
			n_domains += 1;
		if (n_domains > MAX_DOMAINS) {
			fprintf(stderr, "too many domains\n");
			goto bad_usage;
		}
	} else {
		n_domains = 1;
	}

	if (sad_create(cfg)) {
		goto end;
	}

	for (i = 0; i < n_domains; i++) {
		domains[i] = settings;
		domains[i].agent = pmc_agent_create();
		if (!domains[i].agent) {
			return -1;
		}

		if (settings.forced_sync_offset)
			pmc_agent_set_sync_offset(domains[i].agent, offset);
	}

	if (autocfg) {
		for (i = 0; i < n_domains; i++) {
			if (rt && i + 1 == n_domains) {
				if (auto_init_rt(&domains[n_domains - 1],
						 rt == 1) < 0)
					goto end;
				continue;
			}

			snprintf(uds_local, sizeof(uds_local),
				 "phc2sys.%d.%d", getpid(), i);

			if (uds_remote_cnt > i)
				config_set_string(cfg, "uds_address",
						  uds_remotes[i]);
			if (domain_number_cnt > i)
				config_set_int(cfg, "domainNumber",
					       domain_numbers[i]);

			if (init_pmc_node(cfg, domains[i].agent, uds_local,
					  phc2sys_recv_subscribed, &domains[i]))
				goto end;
			if (auto_init_ports(&domains[i]) < 0)
				goto end;
		}

		for (i = 0; i < dst_cnt; i++) {
			r = phc2sys_static_dst_configuration(&domains[0],
							     dst_names[i]);
			if (r)
				goto end;
		}

		r = do_loop(domains, n_domains);
		goto end;
	}

	for (i = 0; i < dst_cnt; i++) {
		r = phc2sys_static_dst_configuration(&domains[0], dst_names[i]);
		if (r) {
			goto end;
		}
	}

	r = phc2sys_static_src_configuration(&domains[0], src_name);
	if (r) {
		goto end;
	}

	r = -1;

	if (wait_sync || !domains[0].forced_sync_offset) {
		snprintf(uds_local, sizeof(uds_local), "phc2sys.%d", getpid());

		if (uds_remote_cnt > 0)
			config_set_string(cfg, "uds_address",
					  uds_remotes[uds_remote_cnt - 1]);
		if (domain_number_cnt > 0)
			config_set_int(cfg, "domainNumber",
				       domain_numbers[domain_number_cnt - 1]);

		if (init_pmc_node(cfg, domains[0].agent, uds_local,
				  phc2sys_recv_subscribed, &domains[0]))
			goto end;

		while (wait_sync && is_running()) {
			r = run_pmc_wait_sync(domains[0].agent, 1000);
			if (r < 0)
				goto end;
			if (r > 0)
				break;
			else
				pr_notice("Waiting for ptp4l...");
		}

		if (!domains[0].forced_sync_offset) {
			r = pmc_agent_query_utc_offset(domains[0].agent, 1000);
			if (r) {
				pr_err("failed to get UTC offset");
				goto end;
			}
		}

		if (domains[0].forced_sync_offset ||
		    !phc2sys_using_systemclock(&domains[0]) ||
		    (hardpps_configured(pps_fd) && !src_name)) {
			pmc_agent_disable(domains[0].agent);
		}
	}

	if (hardpps_configured(pps_fd)) {
		struct clock *dst = LIST_FIRST(&domains[0].dst_clocks);

		/* only one destination clock allowed with PPS until we
		 * implement a mean to specify PTP port to PPS mapping */
		dst->servo = servo_add(&domains[0], dst);
		servo_sync_interval(dst->servo, 1.0);
		r = do_pps_loop(&domains[0], dst, pps_fd);
	} else {
		r = do_loop(&domains[0], 1);
	}

end:
	for (i = 0; i < n_domains; i++) {
		if (domains[i].agent)
			pmc_agent_destroy(domains[i].agent);
		clock_cleanup(&domains[i]);
		port_cleanup(&domains[i]);
	}
	config_destroy(cfg);
	msg_cleanup();
	return r;
bad_usage:
	usage(progname);
	config_destroy(cfg);
	return -1;
}
