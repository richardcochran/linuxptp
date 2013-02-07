/**
 * @file sysoff.h
 * @brief Implements the system offset estimation method.
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
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

#include <stdint.h>

enum {
	SYSOFF_SUPPORTED,
	SYSOFF_COMPILE_TIME_MISSING,
	SYSOFF_RUN_TIME_MISSING,
};

/**
 * Check to see if the PTP_SYS_OFFSET ioctl is supported.
 * @param fd  An open file descriptor to a PHC device.
 * @return  One of the SYSOFF_ enumeration values.
 */
int sysoff_probe(int fd, int n_samples);

/**
 * Measure the offset between a PHC and the system time.
 * @param fd         An open file descriptor to a PHC device.
 * @param n_samples  The number of consecutive readings to make.
 * @param result     The estimated offset in nanoseconds.
 * @param ts         The system time corresponding to the 'result'.
 * @param delay      The delay in reading of the clock in nanoseconds.
 * @return  One of the SYSOFF_ enumeration values.
 */
int sysoff_measure(int fd, int n_samples,
		   int64_t *result, uint64_t *ts, int64_t *delay);
