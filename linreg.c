/**
 * @file linreg.c
 * @brief Implements an adaptive servo based on linear regression.
 * @note Copyright (C) 2014 Miroslav Lichvar <mlichvar@redhat.com>
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
#include <math.h>

#include "linreg.h"
#include "print.h"
#include "servo_private.h"

/* Maximum and minimum number of points used in regression,
   defined as a power of 2 */
#define MAX_SIZE 6
#define MIN_SIZE 2

#define MAX_POINTS (1 << MAX_SIZE)

/* Smoothing factor used for long-term prediction error */
#define ERR_SMOOTH 0.02
/* Number of updates used for initialization */
#define ERR_INITIAL_UPDATES 10
/* Maximum ratio of two err values to be considered equal */
#define ERR_EQUALS 1.05

/* Uncorrected local time vs remote time */
struct point {
	uint64_t x;
	uint64_t y;
	double w;
};

struct result {
	/* Slope and intercept from latest regression */
	double slope;
	double intercept;
	/* Exponential moving average of prediction error */
	double err;
	/* Number of initial err updates */
	int err_updates;
};

struct linreg_servo {
	struct servo servo;
	/* Circular buffer of points */
	struct point points[MAX_POINTS];
	/* Current time in x, y */
	struct point reference;
	/* Number of stored points */
	unsigned int num_points;
	/* Index of the newest point */
	unsigned int last_point;
	/* Remainder from last update of reference.x */
	double x_remainder;
	/* Local time stamp of last update */
	uint64_t last_update;
	/* Regression results for all sizes */
	struct result results[MAX_SIZE - MIN_SIZE + 1];
	/* Selected size */
	unsigned int size;
	/* Current frequency offset of the clock */
	double clock_freq;
	/* Expected interval between updates */
	double update_interval;
	/* Current ratio between remote and local frequency */
	double frequency_ratio;
	/* Upcoming leap second */
	int leap;
};

static void linreg_destroy(struct servo *servo)
{
	struct linreg_servo *s = container_of(servo, struct linreg_servo, servo);
	free(s);
}

static void move_reference(struct linreg_servo *s, int64_t x, int64_t y)
{
	struct result *res;
	unsigned int i;

	s->reference.x += x;
	s->reference.y += y;

	/* Update intercepts for new reference */
	for (i = MIN_SIZE; i <= MAX_SIZE; i++) {
		res = &s->results[i - MIN_SIZE];
		res->intercept += x * res->slope - y;
	}
}

static void update_reference(struct linreg_servo *s, uint64_t local_ts)
{
	double x_interval;
	int64_t y_interval;

	if (s->last_update) {
		y_interval = local_ts - s->last_update;

		/* Remove current frequency correction from the interval */
		x_interval = y_interval / (1.0 + s->clock_freq / 1e9);
		x_interval += s->x_remainder;
		s->x_remainder = x_interval - (int64_t)x_interval;

		move_reference(s, (int64_t)x_interval, y_interval);
	}

	s->last_update = local_ts;
}

static void add_sample(struct linreg_servo *s, int64_t offset, double weight)
{
	s->last_point = (s->last_point + 1) % MAX_POINTS;

	s->points[s->last_point].x = s->reference.x;
	s->points[s->last_point].y = s->reference.y - offset;
	s->points[s->last_point].w = weight;

	if (s->num_points < MAX_POINTS)
		s->num_points++;
}

static void regress(struct linreg_servo *s)
{
	double x, y, y0, e, x_sum, y_sum, xy_sum, x2_sum, w, w_sum;
	unsigned int i, l, n, size;
	struct result *res;

	x_sum = 0.0, y_sum = 0.0, xy_sum = 0.0, x2_sum = 0.0; w_sum = 0.0;
	i = 0;

	y0 = (int64_t)(s->points[s->last_point].y - s->reference.y);

	for (size = MIN_SIZE; size <= MAX_SIZE; size++) {
		n = 1 << size;
		if (n > s->num_points)
			/* Not enough points for this size */
			break;

		res = &s->results[size - MIN_SIZE];

		/* Update moving average of the prediction error */
		if (res->slope) {
			e = fabs(res->intercept - y0);
			if (res->err_updates < ERR_INITIAL_UPDATES) {
				res->err *= res->err_updates;
				res->err += e;
				res->err_updates++;
				res->err /= res->err_updates;
			} else {
				res->err += ERR_SMOOTH * (e - res->err);
			}
		}

		for (; i < n; i++) {
			/* Iterate points from newest to oldest */
			l = (MAX_POINTS + s->last_point - i) % MAX_POINTS;

			x = (int64_t)(s->points[l].x - s->reference.x);
			y = (int64_t)(s->points[l].y - s->reference.y);
			w = s->points[l].w;

			x_sum += x * w;
			y_sum += y * w;
			xy_sum += x * y * w;
			x2_sum += x * x * w;
			w_sum += w;
		}

		/* Get new intercept and slope */
		res->slope = (xy_sum - x_sum * y_sum / w_sum) /
				(x2_sum - x_sum * x_sum / w_sum);
		res->intercept = (y_sum - res->slope * x_sum) / w_sum;
	}
}

static void update_size(struct linreg_servo *s)
{
	struct result *res;
	double best_err;
	int size, best_size;

	/* Find largest size with smallest prediction error */

	best_size = 0;
	best_err = 0.0;

	for (size = MIN_SIZE; size <= MAX_SIZE; size++) {
		res = &s->results[size - MIN_SIZE];
		if ((!best_size && res->slope) ||
		    (best_err * ERR_EQUALS > res->err &&
		     res->err_updates >= ERR_INITIAL_UPDATES)) {
			best_size = size;
			best_err = res->err;
		}
	}

	s->size = best_size;
}

static double linreg_sample(struct servo *servo,
			    int64_t offset,
			    uint64_t local_ts,
			    double weight,
			    enum servo_state *state)
{
	struct linreg_servo *s = container_of(servo, struct linreg_servo, servo);
	struct result *res;
	int corr_interval;

	/*
	 * The current time and the time when will be the frequency of the
	 * clock actually updated is assumed here to be equal to local_ts
	 * (which is the time stamp of the received sync message). As long as
	 * the differences are smaller than the update interval, the loop
	 * should be robust enough to handle this simplification.
	 */

	update_reference(s, local_ts);
	add_sample(s, offset, weight);
	regress(s);

	update_size(s);

	if (s->size < MIN_SIZE) {
		/* Not enough points, wait for more */
		*state = SERVO_UNLOCKED;
		return -s->clock_freq;
	}

	res = &s->results[s->size - MIN_SIZE];

	pr_debug("linreg: points %d slope %.9f intercept %.0f err %.0f",
		 1 << s->size, res->slope, res->intercept, res->err);

	if ((servo->first_update &&
	     servo->first_step_threshold &&
	     servo->first_step_threshold < fabs(res->intercept)) ||
	    (servo->step_threshold &&
	     servo->step_threshold < fabs(res->intercept))) {
		/* The clock will be stepped by offset */
		move_reference(s, 0, -offset);
		s->last_update -= offset;
		*state = SERVO_JUMP;
	} else {
		*state = SERVO_LOCKED;
	}

	/* Set clock frequency to the slope */
	s->clock_freq = 1e9 * (res->slope - 1.0);

	/*
	 * Adjust the frequency to correct the time offset. Use longer
	 * correction interval with larger sizes to reduce the frequency error.
	 * The update interval is assumed to be not affected by the frequency
	 * adjustment. If it is (e.g. phc2sys controlling the system clock), a
	 * correction slowing down the clock will result in an overshoot. With
	 * the system clock's maximum adjustment of 10% that's acceptable.
	 */
	corr_interval = s->size <= 4 ? 1 : s->size / 2;
	s->clock_freq += res->intercept / s->update_interval / corr_interval;

	/* Clamp the frequency to the allowed maximum */
	if (s->clock_freq > servo->max_frequency)
		s->clock_freq = servo->max_frequency;
	else if (s->clock_freq < -servo->max_frequency)
		s->clock_freq = -servo->max_frequency;

	s->frequency_ratio = res->slope / (1.0 + s->clock_freq / 1e9);

	return -s->clock_freq;
}

static void linreg_sync_interval(struct servo *servo, double interval)
{
	struct linreg_servo *s = container_of(servo, struct linreg_servo, servo);

	s->update_interval = interval;
}

static void linreg_reset(struct servo *servo)
{
	struct linreg_servo *s = container_of(servo, struct linreg_servo, servo);
	unsigned int i;

	s->num_points = 0;
	s->last_update = 0;
	s->size = 0;
	s->frequency_ratio = 1.0;

	for (i = MIN_SIZE; i <= MAX_SIZE; i++) {
		s->results[i - MIN_SIZE].slope = 0.0;
		s->results[i - MIN_SIZE].err_updates = 0;
	}
}

static double linreg_rate_ratio(struct servo *servo)
{
	struct linreg_servo *s = container_of(servo, struct linreg_servo, servo);

	return s->frequency_ratio;
}

static void linreg_leap(struct servo *servo, int leap)
{
	struct linreg_servo *s = container_of(servo, struct linreg_servo, servo);

	/*
	 * Move reference when leap second is applied to the reference
	 * time as if the clock was stepped in the opposite direction
	 */
	if (s->leap && !leap)
		move_reference(s, 0, s->leap * 1000000000);

	s->leap = leap;
}

struct servo *linreg_servo_create(int fadj)
{
	struct linreg_servo *s;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->servo.destroy = linreg_destroy;
	s->servo.sample = linreg_sample;
	s->servo.sync_interval = linreg_sync_interval;
	s->servo.reset = linreg_reset;
	s->servo.rate_ratio = linreg_rate_ratio;
	s->servo.leap = linreg_leap;

	s->clock_freq = -fadj;
	s->frequency_ratio = 1.0;

	return &s->servo;
}
