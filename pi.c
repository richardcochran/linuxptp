/**
 * @file pi.c
 * @brief Implements a Proportional Integral clock servo.
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
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

#include "pi.h"
#include "print.h"
#include "servo_private.h"

#define HWTS_KP_SCALE 0.7
#define HWTS_KI_SCALE 0.3
#define SWTS_KP_SCALE 0.1
#define SWTS_KI_SCALE 0.001

#define MAX_KP_NORM_MAX 1.0
#define MAX_KI_NORM_MAX 2.0

#define NSEC_PER_SEC 1000000000
#define FREQ_EST_MARGIN 0.001

/* These take their values from the configuration file. (see ptp4l.c) */
double configured_pi_kp = 0.0;
double configured_pi_ki = 0.0;
double configured_pi_kp_scale = 0.0;
double configured_pi_kp_exponent = -0.3;
double configured_pi_kp_norm_max = 0.7;
double configured_pi_ki_scale = 0.0;
double configured_pi_ki_exponent = 0.4;
double configured_pi_ki_norm_max = 0.3;
double configured_pi_offset = 0.0;
double configured_pi_f_offset = 0.0000001; /* 100 nanoseconds */
int configured_pi_max_freq = 900000000;

struct pi_servo {
	struct servo servo;
	int64_t offset[2];
	uint64_t local[2];
	double drift;
	double maxppb;
	double kp;
	double ki;
	double max_offset;
	double max_f_offset;
	int count;
	int first_update;
};

static void pi_destroy(struct servo *servo)
{
	struct pi_servo *s = container_of(servo, struct pi_servo, servo);
	free(s);
}

static double pi_sample(struct servo *servo,
			int64_t offset,
			uint64_t local_ts,
			enum servo_state *state)
{
	double ki_term, ppb = 0.0;
	double freq_est_interval, localdiff;
	struct pi_servo *s = container_of(servo, struct pi_servo, servo);

	switch (s->count) {
	case 0:
		s->offset[0] = offset;
		s->local[0] = local_ts;
		*state = SERVO_UNLOCKED;
		s->count = 1;
		break;
	case 1:
		s->offset[1] = offset;
		s->local[1] = local_ts;

		/* Make sure the first sample is older than the second. */
		if (s->local[0] >= s->local[1]) {
			*state = SERVO_UNLOCKED;
			s->count = 0;
			break;
		}

		/* Wait long enough before estimating the frequency offset. */
		localdiff = (s->local[1] - s->local[0]) / 1e9;
		localdiff += localdiff * FREQ_EST_MARGIN;
		freq_est_interval = 0.016 / s->ki;
		if (freq_est_interval > 1000.0) {
			freq_est_interval = 1000.0;
		}
		if (localdiff < freq_est_interval) {
			*state = SERVO_UNLOCKED;
			break;
		}

		s->drift += (s->offset[1] - s->offset[0]) * 1e9 /
			(s->local[1] - s->local[0]);
		if (s->drift < -s->maxppb)
			s->drift = -s->maxppb;
		else if (s->drift > s->maxppb)
			s->drift = s->maxppb;

		if (!s->first_update ||
		    (s->max_f_offset && (s->max_f_offset < fabs(offset))) ||
		    (s->max_offset && (s->max_offset < fabs(offset))))
			*state = SERVO_JUMP;
		else
			*state = SERVO_LOCKED;

		s->first_update = 0;
		ppb = s->drift;
		s->count = 2;
		break;
	case 2:
		/*
		 * reset the clock servo when offset is greater than the max
		 * offset value. Note that the clock jump will be performed in
		 * step 1, so it is not necessary to have clock jump
		 * immediately. This allows re-calculating drift as in initial
		 * clock startup.
		 */
		if (s->max_offset && (s->max_offset < fabs(offset))) {
			*state = SERVO_UNLOCKED;
			s->count = 0;
			break;
		}

		ki_term = s->ki * offset;
		ppb = s->kp * offset + s->drift + ki_term;
		if (ppb < -s->maxppb) {
			ppb = -s->maxppb;
		} else if (ppb > s->maxppb) {
			ppb = s->maxppb;
		} else {
			s->drift += ki_term;
		}
		*state = SERVO_LOCKED;
		break;
	}

	return ppb;
}

static void pi_sync_interval(struct servo *servo, double interval)
{
	struct pi_servo *s = container_of(servo, struct pi_servo, servo);

	s->kp = configured_pi_kp_scale * pow(interval, configured_pi_kp_exponent);
	if (s->kp > configured_pi_kp_norm_max / interval)
		s->kp = configured_pi_kp_norm_max / interval;

	s->ki = configured_pi_ki_scale * pow(interval, configured_pi_ki_exponent);
	if (s->ki > configured_pi_ki_norm_max / interval)
		s->ki = configured_pi_ki_norm_max / interval;

	pr_debug("PI servo: sync interval %.3f kp %.3f ki %.6f",
		 interval, s->kp, s->ki);
}

struct servo *pi_servo_create(int fadj, int max_ppb, int sw_ts)
{
	struct pi_servo *s;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->servo.destroy = pi_destroy;
	s->servo.sample  = pi_sample;
	s->servo.sync_interval = pi_sync_interval;
	s->drift         = fadj;
	s->maxppb        = max_ppb;
	s->first_update  = 1;
	s->kp            = 0.0;
	s->ki            = 0.0;

	if (configured_pi_kp && configured_pi_ki) {
		/* Use the constants as configured by the user without
		   adjusting for sync interval unless they make the servo
		   unstable. */
		configured_pi_kp_scale = configured_pi_kp;
		configured_pi_ki_scale = configured_pi_ki;
		configured_pi_kp_exponent = 0.0;
		configured_pi_ki_exponent = 0.0;
		configured_pi_kp_norm_max = MAX_KP_NORM_MAX;
		configured_pi_ki_norm_max = MAX_KI_NORM_MAX;
	} else if (!configured_pi_kp_scale || !configured_pi_ki_scale) {
		if (sw_ts) {
			configured_pi_kp_scale = SWTS_KP_SCALE;
			configured_pi_ki_scale = SWTS_KI_SCALE;
		} else {
			configured_pi_kp_scale = HWTS_KP_SCALE;
			configured_pi_ki_scale = HWTS_KI_SCALE;
		}
	}

	if (configured_pi_offset > 0.0) {
		s->max_offset = configured_pi_offset * NSEC_PER_SEC;
	} else {
		s->max_offset = 0.0;
	}

	if (configured_pi_f_offset > 0.0) {
		s->max_f_offset = configured_pi_f_offset * NSEC_PER_SEC;
	} else {
		s->max_f_offset = 0.0;
	}

	if (configured_pi_max_freq && s->maxppb > configured_pi_max_freq) {
		s->maxppb = configured_pi_max_freq;
	}

	return &s->servo;
}
