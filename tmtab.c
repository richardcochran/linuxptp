/**
 * @file tmtab.c
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
#include "tmtab.h"
#include "tmv.h"

void tmtab_init(struct tmtab *tt, int log_seconds)
{
	int i;
	struct timespec incr, ts = {0, 0};
	uint64_t max, min;

	if (log_seconds < 0) {
		log_seconds *= -1;
		for (i = 1, max = 500000000ULL; i < log_seconds; i++) {
			max >>= 1;
		}
	} else {
		for (i = 0, max = 1000000000ULL; i < log_seconds; i++) {
			max <<= 1;
		}
	}

	min = max / (TMTAB_MAX - 1ULL);

	incr.tv_sec = min / 1000000000ULL;
	incr.tv_nsec = min % 1000000000ULL;

	for (i = 0; i < TMTAB_MAX; i++) {
		ts.tv_sec  += incr.tv_sec;
		ts.tv_nsec += incr.tv_nsec;
		while (ts.tv_nsec >= NS_PER_SEC) {
			ts.tv_nsec -= NS_PER_SEC;
			ts.tv_sec++;
		}
		tt->ts[i] = ts;
	}
}

