/**
 * @file ts2phc_generic_pps_source.c
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>
#include <time.h>

#include "missing.h"
#include "print.h"
#include "ts2phc_generic_pps_source.h"
#include "ts2phc_pps_source_private.h"
#include "util.h"

struct ts2phc_generic_pps_source {
	struct ts2phc_pps_source pps_source;
};

static void ts2phc_generic_pps_source_destroy(struct ts2phc_pps_source *src)
{
	struct ts2phc_generic_pps_source *s =
		container_of(src, struct ts2phc_generic_pps_source, pps_source);
	free(s);
}

/*
 * Returns the time on the PPS source device at which the most recent
 * PPS event was generated.  This implementation assumes that the
 * system time is approximately correct.
 */
static int ts2phc_generic_pps_source_getppstime(struct ts2phc_pps_source *src,
						struct timespec *ts)
{
	struct timex ntx;
	int code;

	memset(&ntx, 0, sizeof(ntx));
	ntx.modes = ADJ_NANO;
	code = adjtimex(&ntx);
	if (code == -1) {
		pr_err("adjtimex failed: %m");
		return -1;
	}
	ts->tv_sec  = ntx.time.tv_sec + ntx.tai;
	ts->tv_nsec = ntx.time.tv_usec;

	return 0;
}

struct ts2phc_pps_source *ts2phc_generic_pps_source_create(struct ts2phc_private *priv,
							   const char *dev)
{
	struct ts2phc_generic_pps_source *src;

	src = calloc(1, sizeof(*src));
	if (!src) {
		return NULL;
	}
	src->pps_source.destroy = ts2phc_generic_pps_source_destroy;
	src->pps_source.getppstime = ts2phc_generic_pps_source_getppstime;

	return &src->pps_source;
}
