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
#include "ds.h"
#include "fsm.h"
#include "missing.h"
#include "notification.h"
#include "ntpshm.h"
#include "phc.h"
#include "pi.h"
#include "pmc_common.h"
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
#define PMC_UPDATE_INTERVAL (60 * NS_PER_SEC)
#define PMC_SUBSCRIBE_DURATION 180	/* 3 minutes */
/* Note that PMC_SUBSCRIBE_DURATION has to be longer than
 * PMC_UPDATE_INTERVAL otherwise subscription will time out before it is
 * renewed.
 */

struct clock {
	LIST_ENTRY(clock) list;
	clockid_t clkid;
	int sysoff_supported;
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

struct node {
	unsigned int stats_max_count;
	int sanity_freq_limit;
	enum servo_type servo_type;
	int phc_readings;
	double phc_interval;
	int sync_offset;
	int forced_sync_offset;
	int utc_offset_traceable;
	int leap;
	int kernel_leap;
	struct pmc *pmc;
	int pmc_ds_requested;
	uint64_t pmc_last_update;
	int state_changed;
	int clock_identity_set;
	struct ClockIdentity clock_identity;
	LIST_HEAD(port_head, port) ports;
	LIST_HEAD(clock_head, clock) clocks;
	struct clock *master;
};

static struct config *phc2sys_config;

static int update_pmc(struct node *node, int subscribe);
static int clock_handle_leap(struct node *node, struct clock *clock,
			     int64_t offset, uint64_t ts);
static int run_pmc_get_utc_offset(struct node *node, int timeout);
static void run_pmc_events(struct node *node);

static clockid_t clock_open(char *device)
{
	struct sk_ts_info ts_info;
	char phc_device[16];
	int clkid;

	/* check if device is CLOCK_REALTIME */
	if (!strcasecmp(device, "CLOCK_REALTIME"))
		return CLOCK_REALTIME;

	/* check if device is valid phc device */
	clkid = phc_open(device);
	if (clkid != CLOCK_INVALID)
		return clkid;

	/* check if device is a valid ethernet device */
	if (sk_get_ts_info(device, &ts_info) || !ts_info.valid) {
		fprintf(stderr, "unknown clock %s: %m\n", device);
		return CLOCK_INVALID;
	}

	if (ts_info.phc_index < 0) {
		fprintf(stderr, "interface %s does not have a PHC\n", device);
		return CLOCK_INVALID;
	}

	sprintf(phc_device, "/dev/ptp%d", ts_info.phc_index);
	clkid = phc_open(phc_device);
	if (clkid == CLOCK_INVALID)
		fprintf(stderr, "cannot open %s: %m\n", device);
	return clkid;
}

static struct clock *clock_add(struct node *node, char *device)
{
	struct clock *c;
	clockid_t clkid = CLOCK_INVALID;
	int max_ppb;
	double ppb;

	if (device) {
		clkid = clock_open(device);
		if (clkid == CLOCK_INVALID)
			return NULL;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		pr_err("failed to allocate memory for a clock");
		return NULL;
	}
	c->clkid = clkid;
	c->servo_state = SERVO_UNLOCKED;
	c->device = strdup(device);

	if (c->clkid == CLOCK_REALTIME) {
		c->source_label = "sys";
		c->is_utc = 1;
	} else {
		c->source_label = "phc";
	}

	if (node->stats_max_count > 0) {
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
	if (node->sanity_freq_limit) {
		c->sanity_check = clockcheck_create(node->sanity_freq_limit);
		if (!c->sanity_check) {
			pr_err("failed to create clock check");
			return NULL;
		}
	}

	clockadj_init(c->clkid);
	ppb = clockadj_get_freq(c->clkid);
	/* The reading may silently fail and return 0, reset the frequency to
	   make sure ppb is the actual frequency of the clock. */
	clockadj_set_freq(c->clkid, ppb);
	if (c->clkid == CLOCK_REALTIME) {
		sysclk_set_leap(0);
		max_ppb = sysclk_max_freq();
	} else {
		max_ppb = phc_max_adj(c->clkid);
		if (!max_ppb) {
			pr_err("clock is not adjustable");
			return NULL;
		}
	}

	c->servo = servo_create(phc2sys_config, node->servo_type,
				-ppb, max_ppb, 0);
	servo_sync_interval(c->servo, node->phc_interval);

	if (clkid != CLOCK_REALTIME)
		c->sysoff_supported = (SYSOFF_SUPPORTED ==
				       sysoff_probe(CLOCKID_TO_FD(clkid),
						    node->phc_readings));

	LIST_INSERT_HEAD(&node->clocks, c, list);
	return c;
}

static struct port *port_get(struct node *node, unsigned int number)
{
	struct port *p;

	LIST_FOREACH(p, &node->ports, list) {
		if (p->number == number)
			return p;
	}
	return NULL;
}

static struct port *port_add(struct node *node, unsigned int number,
			     char *device)
{
	struct port *p;
	struct clock *c = NULL, *tmp;

	p = port_get(node, number);
	if (p)
		return p;
	/* port is a new one, look whether we have the device already on
	 * a different port */
	LIST_FOREACH(tmp, &node->clocks, list) {
		if (!strcmp(tmp->device, device)) {
			c = tmp;
			break;
		}
	}
	if (!c) {
		c = clock_add(node, device);
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
	LIST_INSERT_HEAD(&node->ports, p, list);
	return p;
}

static void clock_reinit(struct clock *clock)
{
	servo_reset(clock->servo);
	clock->servo_state = SERVO_UNLOCKED;

	if (clock->offset_stats) {
		stats_reset(clock->offset_stats);
		stats_reset(clock->freq_stats);
		stats_reset(clock->delay_stats);
	}
}

static void reconfigure(struct node *node)
{
	struct clock *c, *rt = NULL, *src = NULL, *last = NULL;
	int src_cnt = 0, dst_cnt = 0;

	pr_info("reconfiguring after port state change");
	node->state_changed = 0;

	LIST_FOREACH(c, &node->clocks, list) {
		if (c->clkid == CLOCK_REALTIME) {
			rt = c;
			continue;
		}

		if (c->new_state) {
			if (c->new_state == PS_MASTER)
				clock_reinit(c);

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
			pr_info("selecting %s for synchronization", c->device);
			dst_cnt++;
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
	if (dst_cnt > 1 && !src) {
		if (!rt || rt->dest_only) {
			node->master = last;
			/* Reset to original state in next reconfiguration. */
			node->master->new_state = node->master->state;
			node->master->state = PS_SLAVE;
			if (rt)
				rt->state = PS_SLAVE;
			pr_info("no source, selecting %s as the default clock",
				last->device);
			return;
		}
	}
	if (src_cnt > 1) {
		pr_info("multiple master clocks available, postponing sync...");
		node->master = NULL;
		return;
	}
	if (src_cnt > 0 && !src) {
		pr_info("master clock not ready, waiting...");
		node->master = NULL;
		return;
	}
	if (!src_cnt && !dst_cnt) {
		pr_info("no PHC ready, waiting...");
		node->master = NULL;
		return;
	}
	if ((!src_cnt && (!rt || rt->dest_only)) ||
	    (!dst_cnt && !rt)) {
		pr_info("nothing to synchronize");
		node->master = NULL;
		return;
	}
	if (!src_cnt) {
		src = rt;
		rt->state = PS_SLAVE;
	} else if (rt) {
		if (rt->state != PS_MASTER) {
			rt->state = PS_MASTER;
			clock_reinit(rt);
		}
		pr_info("selecting %s for synchronization", rt->device);
	}
	node->master = src;
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

static int64_t get_sync_offset(struct node *node, struct clock *dst)
{
	int direction = node->forced_sync_offset;

	if (!direction)
		direction = dst->is_utc - node->master->is_utc;
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
		pr_info("rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f "
			"delay %5.0f +/- %3.0f",
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev,
			delay_stats.mean, delay_stats.stddev);
	} else {
		pr_info("rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f",
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev);
	}

	stats_reset(clock->offset_stats);
	stats_reset(clock->freq_stats);
	stats_reset(clock->delay_stats);
}

static void update_clock(struct node *node, struct clock *clock,
			 int64_t offset, uint64_t ts, int64_t delay)
{
	enum servo_state state;
	double ppb;

	if (clock_handle_leap(node, clock, offset, ts))
		return;

	offset += get_sync_offset(node, clock);

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
		clockadj_set_freq(clock->clkid, -ppb);
		if (clock->clkid == CLOCK_REALTIME)
			sysclk_set_sync();
		if (clock->sanity_check)
			clockcheck_set_freq(clock->sanity_check, -ppb);
		break;
	}

	if (clock->offset_stats) {
		update_clock_stats(clock, node->stats_max_count, offset, ppb, delay);
	} else {
		if (delay >= 0) {
			pr_info("%s offset %9" PRId64 " s%d freq %+7.0f "
				"delay %6" PRId64,
				node->master->source_label, offset, state, ppb, delay);
		} else {
			pr_info("%s offset %9" PRId64 " s%d freq %+7.0f",
				node->master->source_label, offset, state, ppb);
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

static int do_pps_loop(struct node *node, struct clock *clock, int fd)
{
	int64_t pps_offset, phc_offset, phc_delay;
	uint64_t pps_ts, phc_ts;
	clockid_t src = node->master->clkid;

	node->master->source_label = "pps";

	if (src == CLOCK_INVALID) {
		/* The sync offset can't be applied with PPS alone. */
		node->sync_offset = 0;
	} else {
		enable_pps_output(node->master->clkid);
	}

	while (is_running()) {
		if (!read_pps(fd, &pps_offset, &pps_ts)) {
			continue;
		}

		/* If a PHC is available, use it to get the whole number
		   of seconds in the offset and PPS for the rest. */
		if (src != CLOCK_INVALID) {
			if (!read_phc(src, clock->clkid, node->phc_readings,
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

		if (update_pmc(node, 0) < 0)
			continue;
		update_clock(node, clock, pps_offset, pps_ts, -1);
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

static int do_loop(struct node *node, int subscriptions)
{
	struct timespec interval;
	struct clock *clock;
	uint64_t ts;
	int64_t offset, delay;

	interval.tv_sec = node->phc_interval;
	interval.tv_nsec = (node->phc_interval - interval.tv_sec) * 1e9;

	while (is_running()) {
		clock_nanosleep(CLOCK_MONOTONIC, 0, &interval, NULL);
		if (update_pmc(node, subscriptions) < 0)
			continue;

		if (subscriptions) {
			run_pmc_events(node);
			if (node->state_changed) {
				/* force getting offset, as it may have
				 * changed after the port state change */
				if (run_pmc_get_utc_offset(node, 1000) <= 0) {
					pr_err("failed to get UTC offset");
					continue;
				}
				reconfigure(node);
			}
		}
		if (!node->master)
			continue;

		LIST_FOREACH(clock, &node->clocks, list) {
			if (!update_needed(clock))
				continue;

			if (clock->clkid == CLOCK_REALTIME &&
			    node->master->sysoff_supported) {
				/* use sysoff */
				if (sysoff_measure(CLOCKID_TO_FD(node->master->clkid),
						   node->phc_readings,
						   &offset, &ts, &delay))
					return -1;
			} else {
				/* use phc */
				if (!read_phc(node->master->clkid, clock->clkid,
					      node->phc_readings,
					      &offset, &ts, &delay))
					continue;
			}
			update_clock(node, clock, offset, ts, delay);
		}
	}
	return 0;
}

static int check_clock_identity(struct node *node, struct ptp_message *msg)
{
	if (!node->clock_identity_set)
		return 1;
	return !memcmp(&node->clock_identity,
		       &msg->header.sourcePortIdentity.clockIdentity,
		       sizeof(struct ClockIdentity));
}

static int is_msg_mgt(struct ptp_message *msg)
{
	struct TLV *tlv;

	if (msg_type(msg) != MANAGEMENT)
		return 0;
	if (management_action(msg) != RESPONSE)
		return 0;
	if (msg->tlv_count != 1)
		return 0;
	tlv = (struct TLV *) msg->management.suffix;
	if (tlv->type == TLV_MANAGEMENT)
		return 1;
	if (tlv->type == TLV_MANAGEMENT_ERROR_STATUS)
		return -1;
	return 0;
}

static int get_mgt_id(struct ptp_message *msg)
{
	struct management_tlv *mgt = (struct management_tlv *) msg->management.suffix;
	return mgt->id;
}

static void *get_mgt_data(struct ptp_message *msg)
{
	struct management_tlv *mgt = (struct management_tlv *) msg->management.suffix;
	return mgt->data;
}

static int get_mgt_err_id(struct ptp_message *msg)
{
	struct management_error_status *mgt;

	mgt = (struct management_error_status *)msg->management.suffix;
	return mgt->id;
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

static int clock_compute_state(struct node *node, struct clock *clock)
{
	struct port *p;
	int state = PS_DISABLED;

	LIST_FOREACH(p, &node->ports, list) {
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

static int recv_subscribed(struct node *node, struct ptp_message *msg,
			   int excluded)
{
	int mgt_id, state;
	struct portDS *pds;
	struct port *port;
	struct clock *clock;

	mgt_id = get_mgt_id(msg);
	if (mgt_id == excluded)
		return 0;
	switch (mgt_id) {
	case TLV_PORT_DATA_SET:
		pds = get_mgt_data(msg);
		port = port_get(node, pds->portIdentity.portNumber);
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
			state = clock_compute_state(node, clock);
			if (clock->state != state) {
				clock->new_state = state;
				node->state_changed = 1;
			}
		}
		return 1;
	}
	return 0;
}

static void send_subscription(struct node *node)
{
	struct subscribe_events_np sen;

	memset(&sen, 0, sizeof(sen));
	sen.duration = PMC_SUBSCRIBE_DURATION;
	sen.bitmask[0] = 1 << NOTIFY_PORT_STATE;
	pmc_send_set_action(node->pmc, TLV_SUBSCRIBE_EVENTS_NP, &sen, sizeof(sen));
}

static int init_pmc(struct config *cfg, struct node *node, int domain_number)
{
	char uds_local[MAX_IFNAME_SIZE + 1];

	snprintf(uds_local, sizeof(uds_local), "/var/run/phc2sys.%d",
		 getpid());
	node->pmc = pmc_create(cfg, TRANS_UDS, uds_local, 0, domain_number, 0, 1);
	if (!node->pmc) {
		pr_err("failed to create pmc");
		return -1;
	}

	return 0;
}

/* Return values:
 * 1: success
 * 0: timeout
 * -1: error reported by the other side
 * -2: local error, fatal
 */
static int run_pmc(struct node *node, int timeout, int ds_id,
		   struct ptp_message **msg)
{
#define N_FD 1
	struct pollfd pollfd[N_FD];
	int cnt, res;

	while (1) {
		pollfd[0].fd = pmc_get_transport_fd(node->pmc);
		pollfd[0].events = POLLIN|POLLPRI;
		if (!node->pmc_ds_requested && ds_id >= 0)
			pollfd[0].events |= POLLOUT;

		cnt = poll(pollfd, N_FD, timeout);
		if (cnt < 0) {
			pr_err("poll failed");
			return -2;
		}
		if (!cnt) {
			/* Request the data set again in the next run. */
			node->pmc_ds_requested = 0;
			return 0;
		}

		/* Send a new request if there are no pending messages. */
		if ((pollfd[0].revents & POLLOUT) &&
		    !(pollfd[0].revents & (POLLIN|POLLPRI))) {
			switch (ds_id) {
			case TLV_SUBSCRIBE_EVENTS_NP:
				send_subscription(node);
				break;
			default:
				pmc_send_get_action(node->pmc, ds_id);
				break;
			}
			node->pmc_ds_requested = 1;
		}

		if (!(pollfd[0].revents & (POLLIN|POLLPRI)))
			continue;

		*msg = pmc_recv(node->pmc);

		if (!*msg)
			continue;

		if (!check_clock_identity(node, *msg)) {
			msg_put(*msg);
			*msg = NULL;
			continue;
		}

		res = is_msg_mgt(*msg);
		if (res < 0 && get_mgt_err_id(*msg) == ds_id) {
			node->pmc_ds_requested = 0;
			return -1;
		}
		if (res <= 0 || recv_subscribed(node, *msg, ds_id) ||
		    get_mgt_id(*msg) != ds_id) {
			msg_put(*msg);
			*msg = NULL;
			continue;
		}
		node->pmc_ds_requested = 0;
		return 1;
	}
}

static int run_pmc_wait_sync(struct node *node, int timeout)
{
	struct ptp_message *msg;
	int res;
	void *data;
	Enumeration8 portState;

	while (1) {
		res = run_pmc(node, timeout, TLV_PORT_DATA_SET, &msg);
		if (res <= 0)
			return res;

		data = get_mgt_data(msg);
		portState = ((struct portDS *)data)->portState;
		msg_put(msg);

		switch (portState) {
		case PS_MASTER:
		case PS_SLAVE:
			return 1;
		}
		/* try to get more data sets (for other ports) */
		node->pmc_ds_requested = 1;
	}
}

static int run_pmc_get_utc_offset(struct node *node, int timeout)
{
	struct ptp_message *msg;
	int res;
	struct timePropertiesDS *tds;

	res = run_pmc(node, timeout, TLV_TIME_PROPERTIES_DATA_SET, &msg);
	if (res <= 0)
		return res;

	tds = (struct timePropertiesDS *)get_mgt_data(msg);
	if (tds->flags & PTP_TIMESCALE) {
		node->sync_offset = tds->currentUtcOffset;
		if (tds->flags & LEAP_61)
			node->leap = 1;
		else if (tds->flags & LEAP_59)
			node->leap = -1;
		else
			node->leap = 0;
		node->utc_offset_traceable = tds->flags & UTC_OFF_VALID &&
					     tds->flags & TIME_TRACEABLE;
	} else {
		node->sync_offset = 0;
		node->leap = 0;
		node->utc_offset_traceable = 0;
	}
	msg_put(msg);
	return 1;
}

static int run_pmc_get_number_ports(struct node *node, int timeout)
{
	struct ptp_message *msg;
	int res;
	struct defaultDS *dds;

	res = run_pmc(node, timeout, TLV_DEFAULT_DATA_SET, &msg);
	if (res <= 0)
		return res;

	dds = (struct defaultDS *)get_mgt_data(msg);
	res = dds->numberPorts;
	msg_put(msg);
	return res;
}

static int run_pmc_subscribe(struct node *node, int timeout)
{
	struct ptp_message *msg;
	int res;

	res = run_pmc(node, timeout, TLV_SUBSCRIBE_EVENTS_NP, &msg);
	if (res <= 0)
		return res;
	msg_put(msg);
	return 1;
}

static void run_pmc_events(struct node *node)
{
	struct ptp_message *msg;

	run_pmc(node, 0, -1, &msg);
}

static int run_pmc_port_properties(struct node *node, int timeout,
				   unsigned int port,
				   int *state, int *tstamping, char *iface)
{
	struct ptp_message *msg;
	int res, len;
	struct port_properties_np *ppn;

	pmc_target_port(node->pmc, port);
	while (1) {
		res = run_pmc(node, timeout, TLV_PORT_PROPERTIES_NP, &msg);
		if (res <= 0)
			goto out;

		ppn = get_mgt_data(msg);
		if (ppn->portIdentity.portNumber != port) {
			msg_put(msg);
			continue;
		}

		*state = ppn->port_state;
		*tstamping = ppn->timestamping;
		len = ppn->interface.length;
		if (len > IFNAMSIZ - 1)
			len = IFNAMSIZ - 1;
		memcpy(iface, ppn->interface.text, len);
		iface[len] = '\0';

		msg_put(msg);
		res = 1;
		break;
	}
out:
	pmc_target_all(node->pmc);
	return res;
}

static int run_pmc_clock_identity(struct node *node, int timeout)
{
	struct ptp_message *msg;
	struct defaultDS *dds;
	int res;

	res = run_pmc(node, timeout, TLV_DEFAULT_DATA_SET, &msg);
	if (res <= 0)
		return res;

	dds = (struct defaultDS *)get_mgt_data(msg);
	memcpy(&node->clock_identity, &dds->clockIdentity,
	       sizeof(struct ClockIdentity));
	node->clock_identity_set = 1;
	msg_put(msg);
	return 1;
}

static void close_pmc(struct node *node)
{
	pmc_destroy(node->pmc);
	node->pmc = NULL;
}

static int auto_init_ports(struct node *node, int add_rt)
{
	struct port *port;
	struct clock *clock;
	int number_ports, res;
	unsigned int i;
	int state, timestamping;
	char iface[IFNAMSIZ];

	while (1) {
		res = run_pmc_clock_identity(node, 1000);
		if (res < 0)
			return -1;
		if (res > 0)
			break;
		/* res == 0, timeout */
		pr_notice("Waiting for ptp4l...");
	}

	number_ports = run_pmc_get_number_ports(node, 1000);
	if (number_ports <= 0) {
		pr_err("failed to get number of ports");
		return -1;
	}

	res = run_pmc_subscribe(node, 1000);
	if (res <= 0) {
		pr_err("failed to subscribe");
		return -1;
	}

	for (i = 1; i <= number_ports; i++) {
		res = run_pmc_port_properties(node, 1000, i, &state,
					      &timestamping, iface);
		if (res == -1) {
			/* port does not exist, ignore the port */
			continue;
		}
		if (res <= 0) {
			pr_err("failed to get port properties");
			return -1;
		}
		if (timestamping == TS_SOFTWARE) {
			/* ignore ports with software time stamping */
			continue;
		}
		port = port_add(node, i, iface);
		if (!port)
			return -1;
		port->state = normalize_state(state);
	}
	if (LIST_EMPTY(&node->clocks)) {
		pr_err("no suitable ports available");
		return -1;
	}
	LIST_FOREACH(clock, &node->clocks, list) {
		clock->new_state = clock_compute_state(node, clock);
	}
	node->state_changed = 1;

	if (add_rt) {
		clock = clock_add(node, "CLOCK_REALTIME");
		if (!clock)
			return -1;
		if (add_rt == 1)
			clock->dest_only = 1;
	}

	/* get initial offset */
	if (run_pmc_get_utc_offset(node, 1000) <= 0) {
		pr_err("failed to get UTC offset");
		return -1;
	}
	return 0;
}

/* Returns: -1 in case of error, 0 otherwise */
static int update_pmc(struct node *node, int subscribe)
{
	struct timespec tp;
	uint64_t ts;

	if (clock_gettime(CLOCK_MONOTONIC, &tp)) {
		pr_err("failed to read clock: %m");
		return -1;
	}
	ts = tp.tv_sec * NS_PER_SEC + tp.tv_nsec;

	if (node->pmc &&
	    !(ts > node->pmc_last_update &&
	      ts - node->pmc_last_update < PMC_UPDATE_INTERVAL)) {
		if (subscribe)
			run_pmc_subscribe(node, 0);
		if (run_pmc_get_utc_offset(node, 0) > 0)
			node->pmc_last_update = ts;
	}

	return 0;
}

/* Returns: non-zero to skip clock update */
static int clock_handle_leap(struct node *node, struct clock *clock,
			     int64_t offset, uint64_t ts)
{
	int clock_leap, node_leap = node->leap;

	clock->sync_offset = node->sync_offset;

	if ((node_leap || clock->leap_set) &&
	    clock->is_utc != node->master->is_utc) {
		/* If the master clock is in UTC, get a time stamp from it, as
		   it is the clock which will include the leap second. */
		if (node->master->is_utc) {
			struct timespec tp;
			if (clock_gettime(node->master->clkid, &tp)) {
				pr_err("failed to read clock: %m");
				return -1;
			}
			ts = tp.tv_sec * NS_PER_SEC + tp.tv_nsec;
		}

		/* If the clock will be stepped, the time stamp has to be the
		   new time. Ignore possible 1 second error in UTC offset. */
		if (clock->is_utc && clock->servo_state == SERVO_UNLOCKED)
			ts -= offset + get_sync_offset(node, clock);

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
			    node->kernel_leap)
				sysclk_set_leap(clock_leap);
			else
				servo_leap(clock->servo, clock_leap);
			clock->leap_set = clock_leap;
		}
	}

	if (node->utc_offset_traceable &&
	    clock->utc_offset_set != clock->sync_offset) {
		if (clock->clkid == CLOCK_REALTIME)
			sysclk_set_tai_offset(clock->sync_offset);
		clock->utc_offset_set = clock->sync_offset;
	}

	return 0;
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
		" -c [dev|name]  slave clock (CLOCK_REALTIME)\n"
		" -d [dev]       master PPS device\n"
		" -s [dev|name]  master clock\n"
		" -O [offset]    slave-master time offset (0)\n"
		" -w             wait for ptp4l\n"
		" common options:\n"
		" -E [pi|linreg] clock servo (pi)\n"
		" -P [kp]        proportional constant (0.7)\n"
		" -I [ki]        integration constant (0.3)\n"
		" -S [step]      step threshold (disabled)\n"
		" -F [step]      step threshold only on start (0.00002)\n"
		" -R [rate]      slave clock update rate in HZ (1.0)\n"
		" -N [num]       number of master clock readings per update (5)\n"
		" -L [limit]     sanity frequency limit in ppb (200000000)\n"
		" -M [num]       NTP SHM segment number (0)\n"
		" -u [num]       number of clock updates in summary stats (0)\n"
		" -n [num]       domain number (0)\n"
		" -x             apply leap seconds by servo instead of kernel\n"
		" -z [path]      server address for UDS (/var/run/ptp4l)\n"
		" -l [num]       set the logging level to 'num' (6)\n"
		" -m             print messages to stdout\n"
		" -q             do not print messages to the syslog\n"
		" -v             prints the software version and exits\n"
		" -h             prints this message and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *progname;
	char *src_name = NULL, *dst_name = NULL;
	struct clock *src, *dst;
	struct config *cfg;
	int autocfg = 0, rt = 0;
	int c, domain_number = 0, pps_fd = -1;
	int r = -1, wait_sync = 0;
	int print_level = LOG_INFO, use_syslog = 1, verbose = 0;
	int ntpshm_segment;
	double phc_rate, tmp;
	struct node node = {
		.sanity_freq_limit = 200000000,
		.servo_type = CLOCK_SERVO_PI,
		.phc_readings = 5,
		.phc_interval = 1.0,
		.kernel_leap = 1,
	};

	handle_term_signals();

	cfg = phc2sys_config = config_create();
	if (!cfg) {
		return -1;
	}

	config_set_double(cfg, "pi_proportional_const", KP);
	config_set_double(cfg, "pi_integral_const", KI);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv,
				  "arc:d:s:E:P:I:S:F:R:N:O:L:M:i:u:wn:xz:l:mqvh"))) {
		switch (c) {
		case 'a':
			autocfg = 1;
			break;
		case 'r':
			rt++;
			break;
		case 'c':
			dst_name = strdup(optarg);
			break;
		case 'd':
			pps_fd = open(optarg, O_RDONLY);
			if (pps_fd < 0) {
				fprintf(stderr,
					"cannot open '%s': %m\n", optarg);
				goto end;
			}
			break;
		case 'i':
			fprintf(stderr,
				"'-i' has been deprecated. please use '-s' instead.\n");
		case 's':
			src_name = strdup(optarg);
			break;
		case 'E':
			if (!strcasecmp(optarg, "pi")) {
				node.servo_type = CLOCK_SERVO_PI;
			} else if (!strcasecmp(optarg, "linreg")) {
				node.servo_type = CLOCK_SERVO_LINREG;
			} else if (!strcasecmp(optarg, "ntpshm")) {
				node.servo_type = CLOCK_SERVO_NTPSHM;
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
			node.phc_interval = 1.0 / phc_rate;
			break;
		case 'N':
			if (get_arg_val_i(c, optarg, &node.phc_readings, 1, INT_MAX))
				goto end;
			break;
		case 'O':
			if (get_arg_val_i(c, optarg, &node.sync_offset,
					  INT_MIN, INT_MAX))
				goto end;
			node.forced_sync_offset = -1;
			break;
		case 'L':
			if (get_arg_val_i(c, optarg, &node.sanity_freq_limit, 0, INT_MAX))
				goto end;
			break;
		case 'M':
			if (get_arg_val_i(c, optarg, &ntpshm_segment, INT_MIN, INT_MAX) ||
			    config_set_int(cfg, "ntpshm_segment", ntpshm_segment))
				goto end;
			break;
		case 'u':
			if (get_arg_val_ui(c, optarg, &node.stats_max_count,
					  0, UINT_MAX))
				goto end;
			break;
		case 'w':
			wait_sync = 1;
			break;
		case 'n':
			if (get_arg_val_i(c, optarg, &domain_number, 0, 255))
				goto end;
			break;
		case 'x':
			node.kernel_leap = 0;
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
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX))
				goto end;
			break;
		case 'm':
			verbose = 1;
			break;
		case 'q':
			use_syslog = 0;
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

	if (autocfg && (src_name || dst_name || pps_fd >= 0 || wait_sync || node.forced_sync_offset)) {
		fprintf(stderr,
			"autoconfiguration cannot be mixed with manual config options.\n");
		goto bad_usage;
	}
	if (!autocfg && pps_fd < 0 && !src_name) {
		fprintf(stderr,
			"autoconfiguration or valid source clock must be selected.\n");
		goto bad_usage;
	}

	if (!autocfg && !wait_sync && !node.forced_sync_offset) {
		fprintf(stderr,
			"time offset must be specified using -w or -O\n");
		goto bad_usage;
	}

	if (node.servo_type == CLOCK_SERVO_NTPSHM) {
		node.kernel_leap = 0;
		node.sanity_freq_limit = 0;
	}

	print_set_progname(progname);
	print_set_verbose(verbose);
	print_set_syslog(use_syslog);
	print_set_level(print_level);

	if (autocfg) {
		if (init_pmc(cfg, &node, domain_number))
			goto end;
		if (auto_init_ports(&node, rt) < 0)
			goto end;
		r = do_loop(&node, 1);
		goto end;
	}

	src = clock_add(&node, src_name);
	free(src_name);
	if (!src) {
		fprintf(stderr,
			"valid source clock must be selected.\n");
		goto bad_usage;
	}
	src->state = PS_SLAVE;
	node.master = src;

	dst = clock_add(&node, dst_name ? dst_name : "CLOCK_REALTIME");
	free(dst_name);
	if (!dst) {
		fprintf(stderr,
			"valid destination clock must be selected.\n");
		goto bad_usage;
	}
	dst->state = PS_MASTER;

	if (pps_fd >= 0 && dst->clkid != CLOCK_REALTIME) {
		fprintf(stderr,
			"cannot use a pps device unless destination is CLOCK_REALTIME\n");
		goto bad_usage;
	}

	r = -1;

	if (wait_sync) {
		if (init_pmc(cfg, &node, domain_number))
			goto end;

		while (is_running()) {
			r = run_pmc_wait_sync(&node, 1000);
			if (r < 0)
				goto end;
			if (r > 0)
				break;
			else
				pr_notice("Waiting for ptp4l...");
		}

		if (!node.forced_sync_offset) {
			r = run_pmc_get_utc_offset(&node, 1000);
			if (r <= 0) {
				pr_err("failed to get UTC offset");
				goto end;
			}
		}

		if (node.forced_sync_offset ||
		    (src->clkid != CLOCK_REALTIME && dst->clkid != CLOCK_REALTIME) ||
		    src->clkid == CLOCK_INVALID)
			close_pmc(&node);
	}

	if (pps_fd >= 0) {
		/* only one destination clock allowed with PPS until we
		 * implement a mean to specify PTP port to PPS mapping */
		servo_sync_interval(dst->servo, 1.0);
		r = do_pps_loop(&node, dst, pps_fd);
	} else {
		r = do_loop(&node, 0);
	}

end:
	if (node.pmc)
		close_pmc(&node);
	config_destroy(cfg);
	return r;
bad_usage:
	usage(progname);
	config_destroy(cfg);
	return -1;
}
