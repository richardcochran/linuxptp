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
 * When set to a non-zero value, this variable determines the scale in the
 * formula used to set the proportional constant of the PI controller from the
 * sync interval.
 * kp = min(kp_scale * sync^kp_exponent, kp_norm_max / sync)
 */
extern double configured_pi_kp_scale;

/**
 * This variable determines the exponent in the formula used to set the
 * proportional constant of the PI controller from the sync interval.
 * kp = min(kp_scale * sync^kp_exponent, kp_norm_max / sync)
 */
extern double configured_pi_kp_exponent;

/**
 * This variable determines the normalized maximum in the formula used to set
 * the proportional constant of the PI controller from the sync interval.
 * kp = min(kp_scale * sync^kp_exponent, kp_norm_max / sync)
 */
extern double configured_pi_kp_norm_max;

/**
 * When set to a non-zero value, this variable determines the scale in the
 * formula used to set the integral constant of the PI controller from the
 * sync interval.
 * ki = min(ki_scale * sync^ki_exponent, ki_norm_max / sync)
 */
extern double configured_pi_ki_scale;

/**
 * This variable determines the exponent in the formula used to set the
 * integral constant of the PI controller from the sync interval.
 * ki = min(ki_scale * sync^ki_exponent, ki_norm_max / sync)
 */
extern double configured_pi_ki_exponent;

/**
 * This variable determines the normalized maximum in the formula used to set
 * the integral constant of the PI controller from the sync interval.
 * ki = min(ki_scale * sync^ki_exponent, ki_norm_max / sync)
 */
extern double configured_pi_ki_norm_max;

struct servo *pi_servo_create(int fadj, int sw_ts);

#endif
