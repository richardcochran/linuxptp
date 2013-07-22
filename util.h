/**
 * @file util.h
 * @brief Various little utility functions that do not fit in elsewhere.
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
#ifndef HAVE_UTIL_H
#define HAVE_UTIL_H

#include "config.h"
#include "ddt.h"

/**
 * Table of human readable strings, one for each port state.
 */
extern char *ps_str[];

/**
 * Table of human readable strings, one for each port event.
 */
extern char *ev_str[];

/**
 * Convert a clock identity into a human readable string.
 *
 * Note that this function uses a static global variable to store the
 * result and therefore is not reentrant.
 *
 * @param id  Clock idendtity to show.
 * @return    Pointer to a static global buffer holding the result.
 */
char *cid2str(struct ClockIdentity *id);

/**
 * Convert a port identity into a human readable string.
 *
 * Note that this function uses a static global variable to store the
 * result and therefore is not reentrant.
 *
 * @param id  Port idendtity to show.
 * @return    Pointer to a static global buffer holding the result.
 */
char *pid2str(struct PortIdentity *id);

/**
 * Scan a string containing a port identity and convert it into binary form.
 *
 * @param s       String in human readable form.
 * @param result  Pointer to a buffer to hold the result.
 * @return Zero on success, or -1 if the string is incorrectly formatted.
 */
int str2pid(const char *s, struct PortIdentity *result);

int generate_clock_identity(struct ClockIdentity *ci, char *name);

/**
 * Copies a PTPText to a static_ptp_text. This copies the text into
 * the static_ptp_text.
 * @param dst The static_ptp_text to copy to
 * @param src The PTPText to copy from
 * @return Zero on success, -1 if text in src is too long or not valid
 * UTF8
 */
int static_ptp_text_copy(struct static_ptp_text *dst, const struct PTPText *src);

/**
 * Copies a static_ptp_text to a PTPText. Caller must ensure it's
 * valid to write to the memory after the PTPText struct. The trailing
 * \0 is not copied.
 * @param dst The PTPText to copy to
 * @param src The static_ptp_text to copy from
 */
void ptp_text_copy(struct PTPText *dst, const struct static_ptp_text *src);

/**
 * Sets a PTPText from a null-terminated char*. Caller must ensure it's
 * valid to write to the memory after the PTPText struct. The trailing
 * \0 is not copied.
 * @param dst The PTPText to copy to
 * @param src The text to copy from
 * @return Zero on success, -1 if src is too long
 */
int ptp_text_set(struct PTPText *dst, const char *src);

/**
 * Sets a static_ptp_text from a null-terminated char*.
 * @param dst The static_ptp_text to copy to
 * @param src The text to copy from
 * @return Zero on success, -1 if text in src is too long or not valid
 * UTF8
 */
int static_ptp_text_set(struct static_ptp_text *dst, const char *src);

/**
 * Check if UTC time stamp can be both before and after a leap second.
 *
 * @param ts UTC time stamp in nanoseconds.
 * @return   0 if not, 1 if yes.
 */
int is_utc_ambiguous(uint64_t ts);

/**
 * Get leap second status in given time.
 *
 * @param ts         UTC time stamp in nanoseconds.
 * @param leap_set   Previous leap second status (+1/0/-1).
 * @param leap       Announced leap second (+1/0/-1), will be corrected if
 *                   early/late.
 * @param utc_offset Announced UTC offset, will be corrected if early/late.
 * @return           0 if the leap second passed, +1 if leap second will be
 *                   inserted, -1 if leap second will be deleted.
 */
int leap_second_status(uint64_t ts, int leap_set, int *leap, int *utc_offset);

/**
 * Get an integer value from string with error checking and range
 * specification.
 *
 * @param str_val    String which contains an integer value.
 * @param result     Parsed value is stored in here.
 * @param min        Lower limit. Return OUT_OF_RANGE if parsed value
 *                   is less than min.
 * @param max        Upper Limit. Return OUT_OF_RANGE if parsed value
 *                   is bigger than max.
 * @return           PARSED_OK on success, MALFORMED if str_val is malformed,
 *                   OUT_OF_RANGE if str_val is out of range.
 */
enum parser_result get_ranged_int(const char *str_val, int *result,
				  int min, int max);

/**
 * Get an unsigned integer value from string with error checking and range
 * specification.
 *
 * @param str_val    String which contains an unsigned integer value.
 * @param result     Parsed value is stored in here.
 * @param min        Lower limit. Return OUT_OF_RANGE if parsed value
 *                   is less than min.
 * @param max        Upper Limit. Return OUT_OF_RANGE if parsed value
 *                   is bigger than max.
 * @return           PARSED_OK on success, MALFORMED if str_val is malformed,
 *                   OUT_OF_RANGE if str_val is out of range.
 */
enum parser_result get_ranged_uint(const char *str_val, unsigned int *result,
				   unsigned int min, unsigned int max);

/**
 * Get a double value from string with error checking and range
 * specification.
 *
 * @param str_val    String which contains a double value.
 * @param result     Parsed value is stored in here.
 * @param min        Lower limit. Return OUT_OF_RANGE if parsed value
 *                   is less than min.
 * @param max        Upper Limit. Return OUT_OF_RANGE if parsed value
 *                   is bigger than max.
 * @return           PARSED_OK on success, MALFORMED if str_val is malformed,
 *                   OUT_OF_RANGE if str_val is out of range.
 */
enum parser_result get_ranged_double(const char *str_val, double *result,
				     double min, double max);

/**
 * Common procedure to get an int value from argument for ptp4l and phc2sys.
 *
 * @param op     Character code of an option.
 * @param optarg Option argument string.
 * @param val    Parsed value is stored in here.
 * @param min    Lower limit. Return -1 if parsed value is less than min.
 * @param max    Upper limit. Return -1 if parsed value is bigger than max.
 * @return       0 on success, -1 if some error occurs.
 */
int get_arg_val_i(int op, const char *optarg, int *val, int min, int max);

/**
 * Common procedure to get an unsigned int value from argument for ptp4l
 * and phc2sys.
 *
 * @param op     Character code of an option.
 * @param optarg Option argument string.
 * @param val    Parsed value is stored in here.
 * @param min    Lower limit. Return -1 if parsed value is less than min.
 * @param max    Upper limit. Return -1 if parsed value is bigger than max.
 * @return       0 on success, -1 if some error occurs.
 */
int get_arg_val_ui(int op, const char *optarg, unsigned int *val,
		   unsigned int min, unsigned int max);

/**
 * Common procedure to get a double value from argument for ptp4l and phc2sys.
 *
 * @param op     Character code of an option.
 * @param optarg Option argument string.
 * @param val    Parsed value is stored in here.
 * @param min    Lower limit. Return -1 if parsed value is less than min.
 * @param max    Upper limit. Return -1 if parsed value is bigger than max.
 * @return       0 on success, -1 if some error occurs.
 */
int get_arg_val_d(int op, const char *optarg, double *val,
		  double min, double max);

#endif
