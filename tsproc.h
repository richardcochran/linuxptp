/**
 * @file tsproc.h
 * @brief Time stamp processor.
 * @note Copyright (C) 2015 Miroslav Lichvar <mlichvar@redhat.com>
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
#ifndef HAVE_TSPROC_H
#define HAVE_TSPROC_H

#include "filter.h"

/** Opaque type */
struct tsproc;

/**
 * Defines the available modes.
 */
enum tsproc_mode {
	TSPROC_FILTER,
	TSPROC_RAW,
	TSPROC_FILTER_WEIGHT,
	TSPROC_RAW_WEIGHT,
};

/**
 * Create a new instance of the time stamp processor.
 * @param mode           Time stamp processing mode.
 * @param delay_filter   Type of the filter that will be applied to delay.
 * @param filter_length  Length of the filter.
 * @return               A pointer to a new tsproc on success, NULL otherwise.
 */
struct tsproc *tsproc_create(enum tsproc_mode mode,
			     enum filter_type delay_filter, int filter_length);

/**
 * Destroy a time stamp processor.
 * @param tsp       Pointer obtained via @ref tsproc_create().
 */
void tsproc_destroy(struct tsproc *tsp);

/**
 * Feed a downstream measurement into a time stamp processor.
 * @param tsp       Pointer obtained via @ref tsproc_create().
 * @param remote_ts The remote transmission time.
 * @param local_ts  The local reception time.
 */
void tsproc_down_ts(struct tsproc *tsp, tmv_t remote_ts, tmv_t local_ts);

/**
 * Feed an upstream measurement into a time stamp processor.
 * @param tsp       Pointer obtained via @ref tsproc_create().
 * @param local_ts  The local transmission time.
 * @param remote_ts The remote reception time.
 */
void tsproc_up_ts(struct tsproc *tsp, tmv_t local_ts, tmv_t remote_ts);

/**
 * Set ratio between remote and local clock frequencies.
 * @param tsp               Pointer obtained via @ref tsproc_create().
 * @param clock_rate_ratio  The ratio between frequencies.
 */
void tsproc_set_clock_rate_ratio(struct tsproc *tsp, double clock_rate_ratio);

/**
 * Set delay in a time stamp processor. This can be used to override the last
 * calculated value.
 * @param tsp    Pointer obtained via @ref tsproc_create().
 * @param delay  The new delay.
 */
void tsproc_set_delay(struct tsproc *tsp, tmv_t delay);

/**
 * Update delay in a time stamp processor using new measurements.
 * @param tsp    Pointer obtained via @ref tsproc_create().
 * @param delay  A pointer to store the new delay, may be NULL.
 * @return       0 on success, -1 when missing a measurement.
 */
int tsproc_update_delay(struct tsproc *tsp, tmv_t *delay);

/**
 * Update offset in a time stamp processor using new measurements.
 * @param tsp    Pointer obtained via @ref tsproc_create().
 * @param offset A pointer to store the new offset.
 * @param weight A pointer to store the weight of the sample, may be NULL.
 * @return       0 on success, -1 when missing a measurement.
 */
int tsproc_update_offset(struct tsproc *tsp, tmv_t *offset, double *weight);

/**
 * Reset a time stamp processor.
 * @param tsp    Pointer obtained via @ref tsproc_create().
 * @param full   0 to reset stored measurements (e.g. after clock was stepped),
 *               1 to reset everything (e.g. when remote clock changed).
 */
void tsproc_reset(struct tsproc *tsp, int full);

#endif
