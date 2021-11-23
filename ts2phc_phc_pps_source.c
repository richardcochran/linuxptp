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
#include "ts2phc_phc_pps_source.h"
#include "ts2phc_pps_source_private.h"
#include "util.h"

struct ts2phc_phc_pps_source {
	struct ts2phc_pps_source pps_source;
	clockid_t clkid;
	int channel;
	int fd;
};

static int ts2phc_phc_pps_source_activate(struct config *cfg, const char *dev,
					  struct ts2phc_phc_pps_source *s)
{
	struct ptp_perout_request perout_request;
	struct ptp_pin_desc desc;
	struct timespec ts;

	memset(&desc, 0, sizeof(desc));

	s->channel = config_get_int(cfg, dev, "ts2phc.channel");

	desc.index = config_get_int(cfg, dev, "ts2phc.pin_index");
	desc.func = PTP_PF_PEROUT;
	desc.chan = s->channel;

	if (phc_pin_setfunc(s->clkid, &desc)) {
		pr_warning("Failed to set the pin. Continuing bravely on...");
	}
	if (clock_gettime(s->clkid, &ts)) {
		perror("clock_gettime");
		return -1;
	}
	memset(&perout_request, 0, sizeof(perout_request));
	perout_request.index = s->channel;
	perout_request.start.sec = ts.tv_sec + 2;
	perout_request.start.nsec = 0;
	perout_request.period.sec = 1;
	perout_request.period.nsec = 0;

	if (ioctl(s->fd, PTP_PEROUT_REQUEST2, &perout_request)) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
		return -1;
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
	if (ioctl(m->fd, PTP_PEROUT_REQUEST2, &perout_request)) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
	}
	posix_clock_close(m->clkid);
	free(m);
}

static int ts2phc_phc_pps_source_getppstime(struct ts2phc_pps_source *src,
					    struct timespec *ts)
{
	struct ts2phc_phc_pps_source *s =
		container_of(src, struct ts2phc_phc_pps_source, pps_source);
	return clock_gettime(s->clkid, ts);
}

struct ts2phc_pps_source *ts2phc_phc_pps_source_create(struct config *cfg,
						       const char *dev)
{
	struct ts2phc_phc_pps_source *s;
	int junk;

	s = calloc(1, sizeof(*s));
	if (!s) {
		return NULL;
	}
	s->pps_source.destroy = ts2phc_phc_pps_source_destroy;
	s->pps_source.getppstime = ts2phc_phc_pps_source_getppstime;

	s->clkid = posix_clock_open(dev, &junk);
	if (s->clkid == CLOCK_INVALID) {
		free(s);
		return NULL;
	}
	s->fd = CLOCKID_TO_FD(s->clkid);

	pr_debug("PHC PPS source %s has ptp index %d", dev, junk);

	if (ts2phc_phc_pps_source_activate(cfg, dev, s)) {
		ts2phc_phc_pps_source_destroy(&s->pps_source);
		return NULL;
	}

	return &s->pps_source;
}
