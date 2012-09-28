/**
 * @file pi.h
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
#ifndef HAVE_PI_H
#define HAVE_PI_H

#include "servo.h"

/**
 * When set to a non-zero value, this variable determines the
 * proportional constant for the PI controller.
 */
extern double configured_pi_kp;

/**
 * When set to a non-zero value, this variable determines the
 * integral constant for the PI controller.
 */
extern double configured_pi_ki;

/**
 * When set to a non-zero value, this variable controls the maximum allowed
 * offset before a clock jump occurs instead of the default clock-slewing
 * mechanism
 *
 * Note that this variable is measured in seconds, and allows fractional values.
 */
extern double configured_pi_offset;

struct servo *pi_servo_create(int fadj, int max_ppb, int sw_ts);

#endif
