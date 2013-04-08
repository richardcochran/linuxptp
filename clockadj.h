/**
 * @file clockadj.h
 * @brief Wraps clock_adjtime functionality.
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
#ifndef HAVE_CLOCKADJ_H
#define HAVE_CLOCKADJ_H

#include <inttypes.h>
#include <time.h>

/**
 * Set clock's frequency offset.
 * @param clkid A clock ID obtained using phc_open() or CLOCK_REALTIME.
 * @param freq  The frequency offset in parts per billion (ppb).
 */
void clockadj_set_freq(clockid_t clkid, double freq);

/**
 * Read clock's frequency offset.
 * @param clkid A clock ID obtained using phc_open() or CLOCK_REALTIME.
 * @return      The frequency offset in parts per billion (ppb).
 */
double clockadj_get_freq(clockid_t clkid);

/**
 * Step clock's time.
 * @param clkid A clock ID obtained using phc_open() or CLOCK_REALTIME.
 * @param step  The time step in nanoseconds.
 */
void clockadj_step(clockid_t clkid, int64_t step);

/**
 * Set the system clock to insert/delete leap second at midnight.
 * @param leap  +1 to insert leap second, -1 to delete leap second,
 *              0 to reset the leap state.
 */
void sysclk_set_leap(int leap);

/**
 * Read maximum frequency adjustment of the system clock (CLOCK_REALTIME).
 * @return The maximum frequency adjustment in parts per billion (ppb).
 */
int sysclk_max_freq(void);

/**
 * Mark the system clock as synchronized to let the kernel synchronize
 * the real-time clock (RTC) to it.
 */
void sysclk_set_sync(void);
#endif
