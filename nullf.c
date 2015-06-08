/**
 * @file nullf.c
 * @brief Implements a clock servo that always set the frequency offset to zero.
 * @note Copyright (C) 2015 Richard Cochran <richardcochran@gmail.com>
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

#include "nullf.h"
#include "print.h"
#include "servo_private.h"

struct nullf_servo {
	struct servo servo;
};

static void nullf_destroy(struct servo *servo)
{
	struct nullf_servo *s = container_of(servo, struct nullf_servo, servo);
	free(s);
}

static double nullf_sample(struct servo *servo, int64_t offset,
			   uint64_t local_ts, double weight,
			   enum servo_state *state)
{
	if (!offset) {
		*state = SERVO_LOCKED;
		return 0.0;
	}

	if ((servo->first_update && servo->first_step_threshold &&
	     servo->first_step_threshold < fabs(offset)) ||
	    (servo->step_threshold && servo->step_threshold < fabs(offset))) {
		*state = SERVO_JUMP;
	} else {
		*state = SERVO_UNLOCKED;
	}

	return 0.0;
}

static void nullf_sync_interval(struct servo *servo, double interval)
{
}

static void nullf_reset(struct servo *servo)
{
}

struct servo *nullf_servo_create(void)
{
	struct nullf_servo *s;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->servo.destroy = nullf_destroy;
	s->servo.sample = nullf_sample;
	s->servo.sync_interval = nullf_sync_interval;
	s->servo.reset = nullf_reset;

	return &s->servo;
}
