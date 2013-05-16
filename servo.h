/**
 * @file servo.h
 * @brief Implements a generic clock servo interface.
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
#ifndef HAVE_SERVO_H
#define HAVE_SERVO_H

#include <stdint.h>

/** Opaque type */
struct servo;

/**
 * Defines the available servo cores
 */
enum servo_type {
	CLOCK_SERVO_PI,
};

/**
 * Defines the caller visible states of a clock servo.
 */
enum servo_state {

	/**
	 * The servo is not yet ready to track the master clock.
	 */
	SERVO_UNLOCKED,

	/**
	 * The is ready to track and requests a clock jump to
	 * immediately correct the estimated offset.
	 */
	SERVO_JUMP,

	/**
	 * The servo is tracking the master clock.
	 */
	SERVO_LOCKED,
};

/**
 * Create a new instance of a clock servo.
 * @param type    The type of the servo to create.
 * @param fadj    The clock's current adjustment in parts per billion.
 * @param max_ppb The absolute maxinum adjustment allowed by the clock
 *                in parts per billion. The clock servo will clamp its
 *                output according to this limit.
 * @param sw_ts   Indicates that software time stamping will be used,
 *                and the servo should use more aggressive filtering.
 * @return A pointer to a new servo on success, NULL otherwise.
 */
struct servo *servo_create(enum servo_type type, int fadj, int max_ppb, int sw_ts);

/**
 * Destroy an instance of a clock servo.
 * @param servo Pointer to a servo obtained via @ref servo_create().
 */
void servo_destroy(struct servo *servo);

/**
 * Feed a sample into a clock servo.
 * @param servo     Pointer to a servo obtained via @ref servo_create().
 * @param offset    The estimated clock offset in nanoseconds.
 * @param local_ts  The local time stamp of the sample in nanoseconds.
 * @param state     Returns the servo's state.
 * @return The clock adjustment in parts per billion.
 */
double servo_sample(struct servo *servo,
		    int64_t offset,
		    uint64_t local_ts,
		    enum servo_state *state);

/**
 * Inform a clock servo about the master's sync interval.
 * @param servo   Pointer to a servo obtained via @ref servo_create().
 * @param interval The sync interval in seconds.
 */
void servo_sync_interval(struct servo *servo, double interval);

#endif
