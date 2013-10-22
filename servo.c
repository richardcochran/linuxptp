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

#include "pi.h"
#include "servo_private.h"

struct servo *servo_create(enum servo_type type, int fadj, int max_ppb, int sw_ts)
{
	if (type == CLOCK_SERVO_PI) {
		return pi_servo_create(fadj, max_ppb, sw_ts);
	}
	return NULL;
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
	return servo->sample(servo, offset, local_ts, state);
}

void servo_sync_interval(struct servo *servo, double interval)
{
	servo->sync_interval(servo, interval);
}

void servo_reset(struct servo *servo)
{
	servo->reset(servo);
}
