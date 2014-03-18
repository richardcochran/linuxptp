/**
 * @file servo.c
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
#include <string.h>

#include "linreg.h"
#include "pi.h"
#include "servo_private.h"

#define NSEC_PER_SEC 1000000000

double servo_step_threshold = 0.0;
double servo_first_step_threshold = 0.00002; /* 20 microseconds */
int servo_max_frequency = 900000000;

struct servo *servo_create(enum servo_type type, int fadj, int max_ppb, int sw_ts)
{
	struct servo *servo;

	switch (type) {
	case CLOCK_SERVO_PI:
		servo = pi_servo_create(fadj, sw_ts);
		break;
	case CLOCK_SERVO_LINREG:
		servo = linreg_servo_create(fadj);
		break;
	default:
		return NULL;
	}

	if (servo_step_threshold > 0.0) {
		servo->step_threshold = servo_step_threshold * NSEC_PER_SEC;
	} else {
		servo->step_threshold = 0.0;
	}

	if (servo_first_step_threshold > 0.0) {
		servo->first_step_threshold =
			servo_first_step_threshold * NSEC_PER_SEC;
	} else {
		servo->first_step_threshold = 0.0;
	}

	servo->max_frequency = max_ppb;
	if (servo_max_frequency && servo->max_frequency > servo_max_frequency) {
		servo->max_frequency = servo_max_frequency;
	}

	servo->first_update = 1;

	return servo;
}

void servo_destroy(struct servo *servo)
{
	servo->destroy(servo);
}

double servo_sample(struct servo *servo,
		    int64_t offset,
		    uint64_t local_ts,
		    enum servo_state *state)
{
	double r;

	r = servo->sample(servo, offset, local_ts, state);

	if (*state != SERVO_UNLOCKED)
		servo->first_update = 0;

	return r;
}

void servo_sync_interval(struct servo *servo, double interval)
{
	servo->sync_interval(servo, interval);
}

void servo_reset(struct servo *servo)
{
	servo->reset(servo);
}

double servo_rate_ratio(struct servo *servo)
{
	if (servo->rate_ratio)
		return servo->rate_ratio(servo);

	return 1.0;
}
