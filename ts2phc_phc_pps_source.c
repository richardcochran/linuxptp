/**
 * @file ts2phc_phc_pps_source.c
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <linux/ptp_clock.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "config.h"
#include "missing.h"
#include "phc.h"
#include "print.h"
#include "ts2phc.h"
#include "ts2phc_pps_source_private.h"
#include "ts2phc_pps_source.h"
#include "util.h"

struct ts2phc_phc_pps_source {
	struct ts2phc_pps_source pps_source;
	struct ts2phc_clock *clock;
	int channel;
};

static int ts2phc_phc_pps_source_activate(struct config *cfg, const char *dev,
					  struct ts2phc_phc_pps_source *s)
{
	struct ptp_perout_request perout_request;
	struct ptp_pin_desc desc;
	int32_t perout_phase;
	int32_t pulsewidth;
	struct timespec ts;
	int err;

	memset(&desc, 0, sizeof(desc));

	s->channel = config_get_int(cfg, dev, "ts2phc.channel");

	desc.index = config_get_int(cfg, dev, "ts2phc.pin_index");
	desc.func = PTP_PF_PEROUT;
	desc.chan = s->channel;

	if (phc_pin_setfunc(s->clock->clkid, &desc)) {
		pr_warning("Failed to set the pin. Continuing bravely on...");
	}
	if (clock_gettime(s->clock->clkid, &ts)) {
		perror("clock_gettime");
		return -1;
	}
	perout_phase = config_get_int(cfg, dev, "ts2phc.perout_phase");
	memset(&perout_request, 0, sizeof(perout_request));
	perout_request.index = s->channel;
	perout_request.period.sec = 1;
	perout_request.period.nsec = 0;
	perout_request.flags = 0;
	pulsewidth = config_get_int(cfg, dev, "ts2phc.pulsewidth");
	if (pulsewidth) {
		perout_request.flags |= PTP_PEROUT_DUTY_CYCLE;
		perout_request.on.sec = pulsewidth / NS_PER_SEC;
		perout_request.on.nsec = pulsewidth % NS_PER_SEC;
	}
	if (perout_phase != -1) {
		perout_request.flags |= PTP_PEROUT_PHASE;
		perout_request.phase.sec = perout_phase / NS_PER_SEC;
		perout_request.phase.nsec = perout_phase % NS_PER_SEC;
	} else {
		perout_request.start.sec = ts.tv_sec + 2;
		perout_request.start.nsec = 0;
	}

	err = ioctl(s->clock->fd, PTP_PEROUT_REQUEST2, &perout_request);
	if (err) {
		/* Backwards compatibility with old ts2phc where the pulsewidth
		 * property would be just informative (a way to filter out
		 * events in the case that the PPS sink can only do extts on
		 * both rising and falling edges). There, nothing would be
		 * configured on the PHC PPS source towards achieving that
		 * pulsewidth. So in case the ioctl failed, try again with the
		 * DUTY_CYCLE flag unset, in an attempt to avoid a hard
		 * failure.
		 */
		perout_request.flags &= ~PTP_PEROUT_DUTY_CYCLE;
		memset(&perout_request.rsv, 0, 4 * sizeof(unsigned int));
		err = ioctl(s->clock->fd, PTP_PEROUT_REQUEST2, &perout_request);
	}
	if (err) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
		return err;
	}

	return 0;
}

static void ts2phc_phc_pps_source_destroy(struct ts2phc_pps_source *src)
{
	struct ts2phc_phc_pps_source *m =
		container_of(src, struct ts2phc_phc_pps_source, pps_source);
	struct ptp_perout_request perout_request;

	memset(&perout_request, 0, sizeof(perout_request));
	perout_request.index = m->channel;
	if (ioctl(m->clock->fd, PTP_PEROUT_REQUEST2, &perout_request)) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
	}
	ts2phc_clock_destroy(m->clock);
	free(m);
}

static int ts2phc_phc_pps_source_getppstime(struct ts2phc_pps_source *src,
					    struct timespec *ts)
{
	struct ts2phc_phc_pps_source *s =
		container_of(src, struct ts2phc_phc_pps_source, pps_source);
	return clock_gettime(s->clock->clkid, ts);
}

struct ts2phc_clock *ts2phc_phc_pps_source_get_clock(struct ts2phc_pps_source *src)
{
	struct ts2phc_phc_pps_source *s =
		container_of(src, struct ts2phc_phc_pps_source, pps_source);

	return s->clock;
}

struct ts2phc_pps_source *ts2phc_phc_pps_source_create(struct ts2phc_private *priv,
						       const char *dev)
{
	struct ts2phc_phc_pps_source *s;

	s = calloc(1, sizeof(*s));
	if (!s) {
		return NULL;
	}
	s->pps_source.destroy = ts2phc_phc_pps_source_destroy;
	s->pps_source.getppstime = ts2phc_phc_pps_source_getppstime;
	s->pps_source.get_clock = ts2phc_phc_pps_source_get_clock;

	s->clock = ts2phc_clock_add(priv, dev);
	if (!s->clock) {
		free(s);
		return NULL;
	}
	s->clock->is_target = false;

	pr_debug("PHC PPS source %s has ptp index %d", dev,
		 s->clock->phc_index);

	if (ts2phc_phc_pps_source_activate(priv->cfg, dev, s)) {
		ts2phc_phc_pps_source_destroy(&s->pps_source);
		return NULL;
	}

	return &s->pps_source;
}
