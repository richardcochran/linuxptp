/**
 * @file filter.c
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

#include "filter_private.h"
#include "mave.h"

struct filter *filter_create(enum filter_type type, int length)
{
	switch (type) {
	case FILTER_MOVING_AVERAGE:
		return mave_create(length);
	default:
		return NULL;
	}
}

void filter_destroy(struct filter *filter)
{
	filter->destroy(filter);
}

tmv_t filter_sample(struct filter *filter, tmv_t sample)
{
	return filter->sample(filter, sample);
}

void filter_reset(struct filter *filter)
{
	filter->reset(filter);
}
