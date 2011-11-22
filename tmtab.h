/**
 * @file tmtab.h
 * @brief Implements a table of time out values.
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
#ifndef HAVE_TMTAB_H
#define HAVE_TMTAB_H

#include <time.h>

/*
 * Let 'D' be the logMinDelayReqInterval
 * and 'S' be the logSyncInterval.
 *
 * The delay request interval ranges from zero to 2^{D+1} seconds.
 * The standard requires that
 *
 *    S <= D <= S+5
 *
 * and the timeout granularity not more than 2^{S-4} seconds.
 * Thus, the minimum required number of grains is given by
 *
 *    2^{D+1} / 2^{S-4} = 2^{D-S+5}
 *
 * and finds a minimum of 2^5 and a maximum of 2^10.
 *
 * The timeout table allows for the maximum number of grains required.
 *
 * Note that the table is made to be biased so that when sampling the
 * table randomly, the average delay value will be slightly larger
 * than logMinDelayReqInterval, in order to satisfy the wording of the
 * standard.
 */
#define TMTAB_MAX 1024

struct tmtab {
	struct timespec ts[TMTAB_MAX];
};

void tmtab_init(struct tmtab *tt, int log_seconds);

#endif
