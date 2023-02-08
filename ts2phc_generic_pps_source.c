/**
 * @file ts2phc_generic_pps_source.c
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>
#include <time.h>

#include "lstab.h"
#include "missing.h"
#include "print.h"
#include "ts2phc_generic_pps_source.h"
#include "ts2phc_pps_source_private.h"
#include "util.h"

struct ts2phc_generic_pps_source {
	struct ts2phc_pps_source pps_source;
	struct lstab *lstab;
};

static void ts2phc_generic_pps_source_destroy(struct ts2phc_pps_source *src)
{
	struct ts2phc_generic_pps_source *s =
		container_of(src, struct ts2phc_generic_pps_source, pps_source);

	if (s->lstab) {
		lstab_destroy(s->lstab);
	}

	free(s);
}

static int get_ntx(struct timex *ntx)
{
	int code;

	if (!ntx)
		return -1;

	memset(ntx, 0, sizeof(*ntx));
	ntx->modes = ADJ_NANO;
	code = adjtimex(ntx);
	if (code == -1) {
		pr_err("adjtimex failed: %m");
		return -1;
	}
	return 0;
}

/*
 * Returns the time on the PPS source device at which the most recent
 * PPS event was generated.  This implementation assumes that the
 * system time is approximately correct.
 */
static int ts2phc_generic_pps_source_getppstime(struct ts2phc_pps_source *src,
						struct timespec *ts)
{
	struct ts2phc_generic_pps_source *s =
		container_of(src, struct ts2phc_generic_pps_source, pps_source);
	enum lstab_result result;
	int64_t utc_time;
	struct timex ntx;
	int tai_offset;

	if (get_ntx(&ntx)) {
		return -1;
	}

	tai_offset = ntx.tai;

	/* When TAI offset is not set in system - try to get it from leapfile */
	if (tai_offset == 0) {
		if (!s->lstab) {
			return -1;
		}

		utc_time = ntx.time.tv_sec;
		result = lstab_utc2tai(s->lstab, utc_time, &tai_offset);

		switch (result) {
		case LSTAB_OK:
			break;
		case LSTAB_UNKNOWN:
			pr_err("Unable to find utc time in leap second table");
			return -1;
		case LSTAB_EXPIRED:
			pr_err("UTC time is past leap second table expiry date");
			return -1;
		case LSTAB_AMBIGUOUS:
			pr_err("UTC time stamp is ambiguous");
			return -1;
		}
	}

	ts->tv_sec  = ntx.time.tv_sec + tai_offset;
	ts->tv_nsec = ntx.time.tv_usec;

	return 0;
}

struct ts2phc_pps_source *ts2phc_generic_pps_source_create(struct ts2phc_private *priv,
							   const char *dev)
{
	struct ts2phc_generic_pps_source *src;
	const char *leapfile;
	struct timex ntx;

	if (get_ntx(&ntx)) {
		return NULL;
	}

	src = calloc(1, sizeof(*src));
	if (!src) {
		return NULL;
	}

	if (ntx.tai == 0) {
		pr_err("UTC-TAI offset not set in system! Trying to revert to leapfile");

		leapfile = config_get_string(priv->cfg, NULL, "leapfile");
		src->lstab = lstab_create(leapfile);
		if (!src->lstab) {
			free(src);
			return NULL;
		}
	}

	src->pps_source.destroy = ts2phc_generic_pps_source_destroy;
	src->pps_source.getppstime = ts2phc_generic_pps_source_getppstime;

	return &src->pps_source;
}
