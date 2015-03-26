/**
 * @file tsproc.c
 * @note Copyright (C) 2015 Miroslav Lichvar <mlichvar@redhat.com>
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

#include <stdlib.h>
#include <inttypes.h>

#include "tsproc.h"
#include "filter.h"
#include "print.h"

struct tsproc {
	/* Processing options */
	int raw_mode;
	int weighting;

	/* Current ratio between remote and local clock frequency */
	double clock_rate_ratio;

	/* Latest down measurement */
	tmv_t t1;
	tmv_t t2;

	/* Latest up measurement */
	tmv_t t3;
	tmv_t t4;

	/* Current filtered delay */
	tmv_t filtered_delay;

	/* Delay filter */
	struct filter *delay_filter;
};

struct tsproc *tsproc_create(enum tsproc_mode mode,
			     enum filter_type delay_filter, int filter_length)
{
	struct tsproc *tsp;

	tsp = calloc(1, sizeof(*tsp));
	if (!tsp)
		return NULL;

	switch (mode) {
	case TSPROC_FILTER:
		tsp->raw_mode = 0;
		tsp->weighting = 0;
		break;
	case TSPROC_RAW:
		tsp->raw_mode = 1;
		tsp->weighting = 0;
		break;
	case TSPROC_FILTER_WEIGHT:
		tsp->raw_mode = 0;
		tsp->weighting = 1;
		break;
	case TSPROC_RAW_WEIGHT:
		tsp->raw_mode = 1;
		tsp->weighting = 1;
		break;
	default:
		free(tsp);
		return NULL;
	}

	tsp->delay_filter = filter_create(delay_filter, filter_length);
	if (!tsp->delay_filter) {
		free(tsp);
		return NULL;
	}

	tsp->clock_rate_ratio = 1.0;

	return tsp;
}

void tsproc_destroy(struct tsproc *tsp)
{
	filter_destroy(tsp->delay_filter);
	free(tsp);
}

void tsproc_down_ts(struct tsproc *tsp, tmv_t remote_ts, tmv_t local_ts)
{
	tsp->t1 = remote_ts;
	tsp->t2 = local_ts;
}

void tsproc_up_ts(struct tsproc *tsp, tmv_t local_ts, tmv_t remote_ts)
{
	tsp->t3 = local_ts;
	tsp->t4 = remote_ts;
}

void tsproc_set_clock_rate_ratio(struct tsproc *tsp, double clock_rate_ratio)
{
	tsp->clock_rate_ratio = clock_rate_ratio;
}

void tsproc_set_delay(struct tsproc *tsp, tmv_t delay)
{
	tsp->filtered_delay = delay;
}

tmv_t get_raw_delay(struct tsproc *tsp)
{
	tmv_t t23, t41, delay;

	/* delay = ((t2 - t3) * rr + (t4 - t1)) / 2 */

	t23 = tmv_sub(tsp->t2, tsp->t3);
	if (tsp->clock_rate_ratio != 1.0)
		t23 = dbl_tmv(tmv_dbl(t23) * tsp->clock_rate_ratio);
	t41 = tmv_sub(tsp->t4, tsp->t1);
	delay = tmv_div(tmv_add(t23, t41), 2);

	if (delay < 0) {
		pr_debug("negative delay %10" PRId64, delay);
		pr_debug("delay = (t2 - t3) * rr + (t4 - t1)");
		pr_debug("t2 - t3 = %+10" PRId64, t23);
		pr_debug("t4 - t1 = %+10" PRId64, t41);
		pr_debug("rr = %.9f", tsp->clock_rate_ratio);
	}

	return delay;
}

int tsproc_update_delay(struct tsproc *tsp, tmv_t *delay)
{
	tmv_t raw_delay;

	if (tmv_is_zero(tsp->t1) || tmv_is_zero(tsp->t2) ||
	    tmv_is_zero(tsp->t3) || tmv_is_zero(tsp->t4))
		return -1;

	raw_delay = get_raw_delay(tsp);
	tsp->filtered_delay = filter_sample(tsp->delay_filter, raw_delay);

	pr_debug("delay   filtered %10" PRId64 "   raw %10" PRId64,
		 tsp->filtered_delay, raw_delay);

	if (delay)
		*delay = tsp->raw_mode ? raw_delay : tsp->filtered_delay;

	return 0;
}

int tsproc_update_offset(struct tsproc *tsp, tmv_t *offset, double *weight)
{
	tmv_t delay, raw_delay = 0;

	if (tmv_is_zero(tsp->t1) || tmv_is_zero(tsp->t2) ||
	    tmv_is_zero(tsp->t3) || tmv_is_zero(tsp->t4))
		return -1;

	if (tsp->raw_mode || tsp->weighting)
		raw_delay = get_raw_delay(tsp);

	delay = tsp->raw_mode ? raw_delay : tsp->filtered_delay;

	/* offset = t2 - t1 - delay */
	*offset = tmv_sub(tmv_sub(tsp->t2, tsp->t1), delay);

	if (!weight)
		return 0;

	if (tsp->weighting && tsp->filtered_delay > 0 && raw_delay > 0) {
		*weight = (double)tsp->filtered_delay / raw_delay;
		if (*weight > 1.0)
			*weight = 1.0;
	} else {
		*weight = 1.0;
	}

	return 0;
}

void tsproc_reset(struct tsproc *tsp, int full)
{
	tsp->t1 = tmv_zero();
	tsp->t2 = tmv_zero();
	tsp->t3 = tmv_zero();
	tsp->t4 = tmv_zero();

	if (full) {
		tsp->clock_rate_ratio = 1.0;
		filter_reset(tsp->delay_filter);
	}
}
