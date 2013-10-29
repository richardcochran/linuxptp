/**
 * @file filter.h
 * @brief Implements a generic filter interface.
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
#ifndef HAVE_FILTER_H
#define HAVE_FILTER_H

#include "tmv.h"

/** Opaque type */
struct filter;

/**
 * Defines the available filters.
 */
enum filter_type {
	FILTER_MOVING_AVERAGE,
	FILTER_MOVING_MEDIAN,
};

/**
 * Create a new instance of a filter.
 * @param type    The type of the filter to create.
 * @param length  The filter's length.
 * @return A pointer to a new filter on success, NULL otherwise.
 */
struct filter *filter_create(enum filter_type type, int length);

/**
 * Destroy an instance of a filter.
 * @param filter Pointer to a filter obtained via @ref filter_create().
 */
void filter_destroy(struct filter *filter);

/**
 * Feed a sample into a filter.
 * @param filter    Pointer to a filter obtained via @ref filter_create().
 * @param sample    The input sample.
 * @return The output value.
 */
tmv_t filter_sample(struct filter *filter, tmv_t sample);

/**
 * Reset a filter.
 * @param filter   Pointer to a filter obtained via @ref filter_create().
 */
void filter_reset(struct filter *filter);

#endif
