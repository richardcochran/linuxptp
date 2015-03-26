/**
 * @file servo_private.h
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
#ifndef HAVE_SERVO_PRIVATE_H
#define HAVE_SERVO_PRIVATE_H

#include "contain.h"

struct servo {
	double max_frequency;
	double step_threshold;
	double first_step_threshold;
	int first_update;

	void (*destroy)(struct servo *servo);

	double (*sample)(struct servo *servo,
			 int64_t offset, uint64_t local_ts, double weight,
			 enum servo_state *state);

	void (*sync_interval)(struct servo *servo, double interval);

	void (*reset)(struct servo *servo);

	double (*rate_ratio)(struct servo *servo);

	void (*leap)(struct servo *servo, int leap);
};

#endif
