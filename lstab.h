/**
 * @file lstab.h
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_LEAP_SECONDS_H
#define HAVE_LEAP_SECONDS_H

#include <stdint.h>

/** Opaque type */
struct lstab;

/**
 * Creates an instance of a leap second table.
 * @param filename  File from which to initialize the table.  If NULL or empty,
 *                  the hard coded default table will be used.
 * @return A pointer to a leap second table on success, NULL otherwise.
 */
struct lstab *lstab_create(const char *filename);

/**
 * Destroys a leap second table instance.
 * @param lstab  A pointer obtained via lstab_create().
 */
void lstab_destroy(struct lstab *lstab);

/**
 * Enumerates the possible result code for the lstab_utc2tai() method.
 */
enum lstab_result {
	/**
	 * The given UTC value was found in the table, and the
	 * corresponding TAI time is utctime + tai_offset.
	 */
	LSTAB_OK,

	/**
	 * The given UTC value is out of the range of the table, and
	 * the tai_offset return value is not set.
	 */
	LSTAB_UNKNOWN,

	/**
	 * The given UTC value is ambiguous.  The corresponding TAI time is either
	 *
	 *     utctime + tai_offset
	 * or
	 *     utctime + tai_offset + 1.
	 */
	LSTAB_AMBIGUOUS,
};

/**
 * Returns the TAI - UTC offset for a given UTC time value.
 * @param lstab       A pointer obtained via lstab_create().
 * @param utctime     The UTC time value of interest, in seconds.
 * @param tai_offset  Pointer to a buffer to hold the result.
 * @return            One of the lstab_result enumeration values.
 */
enum lstab_result lstab_utc2tai(struct lstab *lstab, uint64_t utctime,
				int *tai_offset);

#endif
