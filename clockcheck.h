/**
 * @file clockcheck.h
 * @brief Implements clock sanity checking.
 * @note Copyright (C) 2013 Miroslav Lichvar <mlichvar@redhat.com>
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
#ifndef HAVE_CLOCKCHECK_H
#define HAVE_CLOCKCHECK_H

#include <stdint.h>

/** Opaque type */
struct clockcheck;

/**
 * Create a new instance of a clock sanity check.
 * @param freq_limit The maximum allowed frequency offset between uncorrected
 *                   clock and the system monotonic clock in ppb.
 * @return A pointer to a new clock check on success, NULL otherwise.
 */
struct clockcheck *clockcheck_create(int freq_limit);

/**
 * Perform the sanity check on a time stamp.
 * @param cc Pointer to a clock check obtained via @ref clockcheck_create().
 * @param ts Time stamp made by the clock in nanoseconds.
 * @return Zero if ts passed the check, non-zero otherwise.
 */
int clockcheck_sample(struct clockcheck *cc, uint64_t ts);

/**
 * Inform clock check about changes in current frequency of the clock.
 * @param cc   Pointer to a clock check obtained via @ref clockcheck_create().
 * @param freq Frequency correction applied to the clock in ppb.
 */
void clockcheck_set_freq(struct clockcheck *cc, int freq);

/**
 * Inform clock check that the clock was stepped.
 * @param cc   Pointer to a clock check obtained via @ref clockcheck_create().
 * @param step Step correction applied to the clock in nanoseconds.
 */
void clockcheck_step(struct clockcheck *cc, int64_t step);

/**
 * Destroy a clock check.
 * @param cc Pointer to a clock check obtained via @ref clockcheck_create().
 */
void clockcheck_destroy(struct clockcheck *cc);

#endif
