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
#include "servo_private.h"

#define HWTS_KP 0.7
#define HWTS_KI 0.3

#define SWTS_KP 0.1
#define SWTS_KI 0.001

#define NSEC_PER_SEC 1000000000

/* These take their values from the configuration file. (see ptp4l.c) */
double configured_pi_kp = 0.0;
double configured_pi_ki = 0.0;
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

struct servo *pi_servo_create(int fadj, int max_ppb, int sw_ts)
{
	struct pi_servo *s;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->servo.destroy = pi_destroy;
	s->servo.sample  = pi_sample;
	s->drift         = fadj;
	s->maxppb        = max_ppb;
	s->first_update  = 1;

	if (configured_pi_kp && configured_pi_ki) {
		s->kp = configured_pi_kp;
		s->ki = configured_pi_ki;
	} else if (sw_ts) {
		s->kp = SWTS_KP;
		s->ki = SWTS_KI;
	} else {
		s->kp = HWTS_KP;
		s->ki = HWTS_KI;
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
