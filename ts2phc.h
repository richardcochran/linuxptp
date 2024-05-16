/**
 * @file ts2phc.h
 * @brief Structure definitions for ts2phc
 * @note Copyright 2020-2022 Vladimir Oltean <olteanv@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_H
#define HAVE_TS2PHC_H

#include <stdbool.h>
#include <sys/queue.h>
#include <time.h>

#include "pmc_agent.h"
#include "servo.h"
#include "ts2phc_pps_source.h"
#include "ts2phc_pps_sink.h"

struct ts2phc_sink_array;

#define SERVO_SYNC_INTERVAL    1.0

struct ts2phc_clock {
	LIST_ENTRY(ts2phc_clock) list;
	clockid_t clkid;
	int fd;
	int phc_index;
	enum port_state state;
	enum port_state new_state;
	struct servo *servo;
	enum servo_state servo_state;
	char *name;
	bool no_adj;
	bool is_target;
	bool is_ts_available;
	tmv_t last_ts;
};

struct ts2phc_port {
	LIST_ENTRY(ts2phc_port) list;
	unsigned int number;
	enum port_state state;
	struct ts2phc_clock *clock;
};

struct ts2phc_private {
	struct ts2phc_pps_source *src;
	STAILQ_HEAD(sink_ifaces_head, ts2phc_pps_sink) sinks;
	unsigned int n_sinks;
	struct ts2phc_sink_array *polling_array;
	tmv_t perout_phase;
	struct config *cfg;
	struct pmc_agent *agent;
	struct ts2phc_clock *ref_clock;
	bool state_changed;
	LIST_HEAD(port_head, ts2phc_port) ports;
	LIST_HEAD(clock_head, ts2phc_clock) clocks;
	int holdover_length;
	time_t holdover_start;
};

struct ts2phc_clock *ts2phc_clock_add(struct ts2phc_private *priv,
				      const char *device);
void ts2phc_clock_destroy(struct ts2phc_clock *clock);
void ts2phc_clock_add_tstamp(struct ts2phc_clock *clock, tmv_t ts);

#endif
