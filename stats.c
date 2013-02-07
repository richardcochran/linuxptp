/**
 * @file stats.c
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
#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "stats.h"

struct stats {
	unsigned int num;
	double min;
	double max;
	double mean;
	double sum_sqr;
	double sum_diff_sqr;
};

struct stats *stats_create(void)
{
	struct stats *stats;

	stats = calloc(1, sizeof *stats);
	return stats;
}

void stats_destroy(struct stats *stats)
{
	free(stats);
}

void stats_add_value(struct stats *stats, double value)
{
	double old_mean = stats->mean;

	if (!stats->num || stats->max < value)
		stats->max = value;
	if (!stats->num || stats->min > value)
		stats->min = value;

	stats->num++;
	stats->mean = old_mean + (value - old_mean) / stats->num;
	stats->sum_sqr += value * value;
	stats->sum_diff_sqr += (value - old_mean) * (value - stats->mean);
}

unsigned int stats_get_num_values(struct stats *stats)
{
	return stats->num;
}

int stats_get_result(struct stats *stats, struct stats_result *result)
{
	if (!stats->num)
		return -1;

	result->min = stats->min;
	result->max = stats->max;
	result->max_abs = stats->max > -stats->min ? stats->max : -stats->min;
	result->mean = stats->mean;
	result->rms = sqrt(stats->sum_sqr / stats->num);
	result->stddev = sqrt(stats->sum_diff_sqr / stats->num);

	return 0;
}

void stats_reset(struct stats *stats)
{
	memset(stats, 0, sizeof *stats);
}
