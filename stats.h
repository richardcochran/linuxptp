/**
 * @file stats.h
 * @brief Implements various statistics.
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
#ifndef HAVE_STATS_H
#define HAVE_STATS_H

/** Opaque type */
struct stats;

/**
 * Create a new instance of statistics.
 * @return A pointer to a new stats on success, NULL otherwise.
 */
struct stats *stats_create(void);

/**
 * Destroy an instance of stats.
 * @param servo Pointer to stats obtained via @ref stats_create().
 */
void stats_destroy(struct stats *stats);

/**
 * Add a new value to the stats.
 * @param stats Pointer to stats obtained via @ref stats_create().
 * @param value The measured value.
 */
void stats_add_value(struct stats *stats, double value);

/**
 * Get the number of values collected in the stats so far.
 * @param stats Pointer to stats obtained via @ref stats_create().
 * @return      The number of values.
 */
unsigned int stats_get_num_values(struct stats *stats);

struct stats_result {
	double min;
	double max;
	double max_abs;
	double mean;
	double rms;
	double stddev;
};

/**
 * Obtain the results of the calculated statistics.
 * @param stats        Pointer to stats obtained via @ref stats_create().
 * @param stats_result Pointer to stats_result to store the results.
 * @return             Zero on success, non-zero if no values were added.
 */
int stats_get_result(struct stats *stats, struct stats_result *result);

/**
 * Reset all statistics.
 * @param stats Pointer to stats obtained via @ref stats_create().
 */
void stats_reset(struct stats *stats);

#endif
