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

#include "pi.h"
#include "servo_private.h"

#define HWTS_KP 0.7
#define HWTS_KI 0.3

#define SWTS_KP 0.1
#define SWTS_KI 0.001

struct pi_servo {
	struct servo servo;
	double offset[2];
	double local[2];
	double drift;
	double maxppb;
	double kp;
	double ki;
	int count;
};

static void pi_destroy(struct servo *servo)
{
	struct pi_servo *s = container_of(servo, struct pi_servo, servo);
	free(s);
}

static double pi_sample(struct servo *servo,
			double offset,
			double local_ts,
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
		*state = SERVO_UNLOCKED;
		s->count = 2;
		break;
	case 2:
		s->drift = (s->offset[1] - s->offset[0]) /
			(s->local[1] - s->local[0]);
		*state = SERVO_UNLOCKED;
		s->count = 3;
		break;
	case 3:
		*state = SERVO_JUMP;
		s->count = 4;
		break;
	case 4:
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

struct servo *pi_servo_create(int max_ppb, int sw_ts)
{
	struct pi_servo *s;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->servo.destroy = pi_destroy;
	s->servo.sample  = pi_sample;
	s->maxppb        = max_ppb;

	if (sw_ts) {
		s->kp = SWTS_KP;
		s->ki = SWTS_KI;
	} else {
		s->kp = HWTS_KP;
		s->ki = HWTS_KI;
	}

	return &s->servo;
}
