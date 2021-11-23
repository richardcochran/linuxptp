/**
 * @file ts2phc_pps_sink.c
 * @brief Utility program to synchronize the PHC clock to external events
 * @note Copyright (C) 2019 Balint Ferencz <fernya@sch.bme.hu>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <errno.h>
#include <linux/ptp_clock.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>

#include "clockadj.h"
#include "config.h"
#include "missing.h"
#include "phc.h"
#include "print.h"
#include "servo.h"
#include "ts2phc_pps_sink.h"
#include "ts2phc_pps_source.h"
#include "util.h"

#define NS_PER_SEC		1000000000LL
#define SAMPLE_WEIGHT		1.0
#define SERVO_SYNC_INTERVAL	1.0

struct ts2phc_pps_sink {
	char *name;
	STAILQ_ENTRY(ts2phc_pps_sink) list;
	struct ptp_pin_desc pin_desc;
	enum servo_state state;
	unsigned int polarity;
	int32_t correction;
	uint32_t ignore_lower;
	uint32_t ignore_upper;
	struct servo *servo;
	clockid_t clk;
	int no_adj;
	int fd;
};

struct ts2phc_sink_array {
	struct ts2phc_pps_sink **sink;
	struct pollfd *pfd;
} polling_array;

struct ts2phc_source_timestamp {
	struct timespec ts;
	bool valid;
};

enum extts_result {
	EXTTS_ERROR	= -1,
	EXTTS_OK	= 0,
	EXTTS_IGNORE	= 1,
};

static enum extts_result
ts2phc_pps_sink_offset(struct ts2phc_pps_sink *sink,
		       struct ts2phc_source_timestamp ts,
		       int64_t *offset, uint64_t *local_ts);

static STAILQ_HEAD(pps_sink_ifaces_head, ts2phc_pps_sink) ts2phc_sinks =
	STAILQ_HEAD_INITIALIZER(ts2phc_sinks);

static unsigned int ts2phc_n_sinks;

static int ts2phc_pps_sink_array_create(void)
{
	struct ts2phc_pps_sink *sink;
	unsigned int i;

	if (polling_array.sink) {
		return 0;
	}
	polling_array.sink = malloc(ts2phc_n_sinks * sizeof(*polling_array.sink));
	if (!polling_array.sink) {
		pr_err("low memory");
		return -1;
	}
	polling_array.pfd = malloc(ts2phc_n_sinks * sizeof(*polling_array.pfd));
	if (!polling_array.pfd) {
		pr_err("low memory");
		free(polling_array.sink);
		polling_array.sink = NULL;
		return -1;
	}
	i = 0;
	STAILQ_FOREACH(sink, &ts2phc_sinks, list) {
		polling_array.sink[i] = sink;
		i++;
	}
	for (i = 0; i < ts2phc_n_sinks; i++) {
		polling_array.pfd[i].events = POLLIN | POLLPRI;
		polling_array.pfd[i].fd = polling_array.sink[i]->fd;
	}
	return 0;
}

static void ts2phc_pps_sink_array_destroy(void)
{
	free(polling_array.sink);
	free(polling_array.pfd);
	polling_array.sink = NULL;
	polling_array.pfd = NULL;
}

static int ts2phc_pps_sink_clear_fifo(struct ts2phc_pps_sink *sink)
{
	struct pollfd pfd = {
		.events = POLLIN | POLLPRI,
		.fd = sink->fd,
	};
	struct ptp_extts_event event;
	int cnt, size;

	while (1) {
		cnt = poll(&pfd, 1, 0);
		if (cnt < 0) {
			if (EINTR == errno) {
				continue;
			} else {
				pr_emerg("poll failed");
				return -1;
			}
		} else if (!cnt) {
			break;
		}
		size = read(pfd.fd, &event, sizeof(event));
		if (size != sizeof(event)) {
			pr_err("read failed");
			return -1;
		}
		pr_debug("%s SKIP extts index %u at %lld.%09u",
			 sink->name, event.index, event.t.sec, event.t.nsec);
	}

	return 0;
}

static struct ts2phc_pps_sink *ts2phc_pps_sink_create(struct config *cfg,
						      const char *device)
{
	enum servo_type servo = config_get_int(cfg, NULL, "clock_servo");
	int err, fadj, junk, max_adj, pulsewidth;
	struct ptp_extts_request extts;
	struct ts2phc_pps_sink *sink;

	sink = calloc(1, sizeof(*sink));
	if (!sink) {
		pr_err("low memory");
		return NULL;
	}
	sink->name = strdup(device);
	if (!sink->name) {
		pr_err("low memory");
		free(sink);
		return NULL;
	}
	sink->pin_desc.index = config_get_int(cfg, device, "ts2phc.pin_index");
	sink->pin_desc.func = PTP_PF_EXTTS;
	sink->pin_desc.chan = config_get_int(cfg, device, "ts2phc.channel");
	sink->polarity = config_get_int(cfg, device, "ts2phc.extts_polarity");
	sink->correction = config_get_int(cfg, device, "ts2phc.extts_correction");

	pulsewidth = config_get_int(cfg, device, "ts2phc.pulsewidth");
	pulsewidth /= 2;
	sink->ignore_upper = 1000000000 - pulsewidth;
	sink->ignore_lower = pulsewidth;

	sink->clk = posix_clock_open(device, &junk);
	if (sink->clk == CLOCK_INVALID) {
		pr_err("failed to open clock");
		goto no_posix_clock;
	}
	sink->no_adj = config_get_int(cfg, NULL, "free_running");
	sink->fd = CLOCKID_TO_FD(sink->clk);

	pr_debug("PPS sink %s has ptp index %d", device, junk);

	fadj = (int) clockadj_get_freq(sink->clk);
	/* Due to a bug in older kernels, the reading may silently fail
	   and return 0. Set the frequency back to make sure fadj is
	   the actual frequency of the clock. */
	if (!sink->no_adj) {
		clockadj_set_freq(sink->clk, fadj);
	}
	max_adj = phc_max_adj(sink->clk);

	sink->servo = servo_create(cfg, servo, -fadj, max_adj, 0);
	if (!sink->servo) {
		pr_err("failed to create servo");
		goto no_servo;
	}
	servo_sync_interval(sink->servo, SERVO_SYNC_INTERVAL);

	if (phc_number_pins(sink->clk) > 0) {
		err = phc_pin_setfunc(sink->clk, &sink->pin_desc);
		if (err < 0) {
			pr_err("PTP_PIN_SETFUNC request failed");
			goto no_pin_func;
		}
	}

	/*
	 * Disable external time stamping, and then read out any stale
	 * time stamps.
	 */
	memset(&extts, 0, sizeof(extts));
	extts.index = sink->pin_desc.chan;
	extts.flags = 0;
	if (ioctl(sink->fd, PTP_EXTTS_REQUEST2, &extts)) {
		pr_err(PTP_EXTTS_REQUEST_FAILED);
	}
	if (ts2phc_pps_sink_clear_fifo(sink)) {
		goto no_ext_ts;
	}

	return sink;
no_ext_ts:
no_pin_func:
	servo_destroy(sink->servo);
no_servo:
	posix_clock_close(sink->clk);
no_posix_clock:
	free(sink->name);
	free(sink);
	return NULL;
}

static void ts2phc_pps_sink_destroy(struct ts2phc_pps_sink *sink)
{
	struct ptp_extts_request extts;

	memset(&extts, 0, sizeof(extts));
	extts.index = sink->pin_desc.chan;
	extts.flags = 0;
	if (ioctl(sink->fd, PTP_EXTTS_REQUEST2, &extts)) {
		pr_err(PTP_EXTTS_REQUEST_FAILED);
	}
	servo_destroy(sink->servo);
	posix_clock_close(sink->clk);
	free(sink->name);
	free(sink);
}

static int ts2phc_pps_sink_event(struct ts2phc_pps_sink *sink,
				 struct ts2phc_source_timestamp source_ts)
{
	enum extts_result result;
	uint64_t extts_ts;
	int64_t offset;
	double adj;

	result = ts2phc_pps_sink_offset(sink, source_ts, &offset, &extts_ts);
	switch (result) {
	case EXTTS_ERROR:
		return -1;
	case EXTTS_OK:
		break;
	case EXTTS_IGNORE:
		return 0;
	}

	if (sink->no_adj) {
		pr_info("%s source offset %10" PRId64, sink->name, offset);
		return 0;
	}

	if (!source_ts.valid) {
		pr_debug("%s ignoring invalid source time stamp", sink->name);
		return 0;
	}

	adj = servo_sample(sink->servo, offset, extts_ts,
			   SAMPLE_WEIGHT, &sink->state);

	pr_debug("%s source offset %10" PRId64 " s%d freq %+7.0f",
		 sink->name, offset, sink->state, adj);

	switch (sink->state) {
	case SERVO_UNLOCKED:
		break;
	case SERVO_JUMP:
		clockadj_set_freq(sink->clk, -adj);
		clockadj_step(sink->clk, -offset);
		break;
	case SERVO_LOCKED:
	case SERVO_LOCKED_STABLE:
		clockadj_set_freq(sink->clk, -adj);
		break;
	}
	return 0;
}

static enum extts_result
ts2phc_pps_sink_offset(struct ts2phc_pps_sink *sink,
		       struct ts2phc_source_timestamp src,
		       int64_t *offset, uint64_t *local_ts)
{
	struct timespec source_ts = src.ts;
	struct ptp_extts_event event;
	uint64_t event_ns, source_ns;
	int cnt;

	cnt = read(sink->fd, &event, sizeof(event));
	if (cnt != sizeof(event)) {
		pr_err("read extts event failed: %m");
		return EXTTS_ERROR;
	}
	if (event.index != sink->pin_desc.chan) {
		pr_err("extts on unexpected channel");
		return EXTTS_ERROR;
	}
	event_ns = event.t.sec * NS_PER_SEC;
	event_ns += event.t.nsec;

	if (sink->polarity == (PTP_RISING_EDGE | PTP_FALLING_EDGE) &&
	    source_ts.tv_nsec > sink->ignore_lower &&
	    source_ts.tv_nsec < sink->ignore_upper) {

		pr_debug("%s SKIP extts index %u at %lld.%09u src %" PRIi64 ".%ld",
		 sink->name, event.index, event.t.sec, event.t.nsec,
		 (int64_t) source_ts.tv_sec, source_ts.tv_nsec);

		return EXTTS_IGNORE;
	}
	if (source_ts.tv_nsec > 500000000) {
		source_ts.tv_sec++;
	}
	source_ns = source_ts.tv_sec * NS_PER_SEC;
	*offset = event_ns + sink->correction - source_ns;
	*local_ts = event_ns + sink->correction;

	pr_debug("%s extts index %u at %lld.%09u corr %d src %" PRIi64
		 ".%ld diff %" PRId64,
		 sink->name, event.index, event.t.sec, event.t.nsec,
		 sink->correction,
		 (int64_t) source_ts.tv_sec, source_ts.tv_nsec, *offset);

	return EXTTS_OK;
}

/* public methods */

int ts2phc_pps_sink_add(struct config *cfg, const char *name)
{
	struct ts2phc_pps_sink *sink;

	/* Create each interface only once. */
	STAILQ_FOREACH(sink, &ts2phc_sinks, list) {
		if (0 == strcmp(name, sink->name)) {
			return 0;
		}
	}
	sink = ts2phc_pps_sink_create(cfg, name);
	if (!sink) {
		pr_err("failed to create sink");
		return -1;
	}
	STAILQ_INSERT_TAIL(&ts2phc_sinks, sink, list);
	ts2phc_n_sinks++;

	return 0;
}

int ts2phc_pps_sink_arm(void)
{
	struct ptp_extts_request extts;
	struct ts2phc_pps_sink *sink;
	int err;

	memset(&extts, 0, sizeof(extts));

	STAILQ_FOREACH(sink, &ts2phc_sinks, list) {
		extts.index = sink->pin_desc.chan;
		extts.flags = sink->polarity | PTP_ENABLE_FEATURE;
		err = ioctl(sink->fd, PTP_EXTTS_REQUEST2, &extts);
		if (err < 0) {
			pr_err(PTP_EXTTS_REQUEST_FAILED);
			return -1;
		}
	}
	return 0;
}

void ts2phc_pps_sink_cleanup(void)
{
	struct ts2phc_pps_sink *sink;

	ts2phc_pps_sink_array_destroy();

	while ((sink = STAILQ_FIRST(&ts2phc_sinks))) {
		STAILQ_REMOVE_HEAD(&ts2phc_sinks, list);
		ts2phc_pps_sink_destroy(sink);
		ts2phc_n_sinks--;
	}
}

int ts2phc_pps_sink_poll(struct ts2phc_pps_source *src)
{
	struct ts2phc_source_timestamp source_ts;
	unsigned int i;
	int cnt, err;

	if (ts2phc_pps_sink_array_create()) {
		return -1;
	}
	cnt = poll(polling_array.pfd, ts2phc_n_sinks, 2000);
	if (cnt < 0) {
		if (EINTR == errno) {
			return 0;
		} else {
			pr_emerg("poll failed");
			return -1;
		}
	} else if (!cnt) {
		pr_debug("poll returns zero, no events");
		return 0;
	}

	err = ts2phc_pps_source_getppstime(src, &source_ts.ts);
	source_ts.valid = err ? false : true;

	for (i = 0; i < ts2phc_n_sinks; i++) {
		if (polling_array.pfd[i].revents & (POLLIN|POLLPRI)) {
			ts2phc_pps_sink_event(polling_array.sink[i], source_ts);
		}
	}
	return 0;
}
