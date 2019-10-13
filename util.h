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

#include <string.h>
#include <time.h>

#include "address.h"
#include "ddt.h"
#include "ether.h"
#include "transport.h"

#define MAX_PRINT_BYTES 16
#define BIN_BUF_SIZE (MAX_PRINT_BYTES * 3 + 1)

/**
 * Table of human readable strings, one for each port state.
 */
extern const char *ps_str[];

/**
 * Table of human readable strings, one for each port event.
 */
extern const char *ev_str[];

/**
 * Gets a human-readable string for a given timestamp type.
 * @param ts    Timestamp type.
 * @return      Human-readable rendering if TS is valid, otherwise "???".
 */
const char *ts_str(enum timestamp_type ts);

/**
 * Compares two binary addresses for equality.
 * @param type  One of the enumerated transport types.
 * @param a     One address to compare.
 * @param b     The second address to compare.
 * @return      One if the addresses are identical, zero otherwise.
 */
int addreq(enum transport_type type, struct address *a, struct address *b);

static inline uint16_t align16(uint16_t *p)
{
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

char *bin2str_impl(Octet *data, int len, char *buf, int buf_len);

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
 * Compare two clock identities for equality.
 *
 * @param a  First clock identity.
 * @param b  Second clock identity.
 * @return   1 if identities are equal, 0 otherwise.
 */
static inline int cid_eq(struct ClockIdentity *a, struct ClockIdentity *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

/**
 * Counts the number of occurrences of a given character.
 * @param str  String to evaluate.
 * @param c    The character of interest.
 * @return     The number of time 'c' appears in 'str'.
 */
int count_char(const char *str, char c);

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

char *portaddr2str(struct PortAddress *addr);

/**
 * Closes a dynamic posix clock.
 * @param clock  A clock ID obtained via posix_clock_close().
 */
void posix_clock_close(clockid_t clock);

/**
 * Opens a dynamic posix clock by name.
 * @param device     The PHC character device or network interface to open.
 * @param phc_index  Returns the PHC index, if any.
 * @return           A valid clock ID on success or CLOCK_INVALID otherwise.
 */
clockid_t posix_clock_open(const char *device, int *phc_index);

/**
 * Compare two port identities for equality.
 *
 * @param a  First port identity.
 * @param b  Second port identity.
 * @return   1 if identities are equal, 0 otherwise.
 */
static inline int pid_eq(struct PortIdentity *a, struct PortIdentity *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

/**
 * Convert a string containing a network address into binary form.
 * @param type  The network transport type of the address.
 * @param s     String in human readable form.
 * @param addr  Pointer to a buffer to hold the result.
 * @return Zero on success, or -1 if the string is incorrectly formatted.
 */
int str2addr(enum transport_type type, const char *s, struct address *addr);

/**
 * Scan a string containing a MAC address and convert it into binary form.
 *
 * @param s       String in human readable form.
 * @param mac     Pointer to a buffer to hold the result.
 * @return Zero on success, or -1 if the string is incorrectly formatted.
 */
int str2mac(const char *s, unsigned char mac[MAC_LEN]);

/**
 * Scan a string containing a clock identity and convert it into binary form.
 *
 * @param s       String in human readable form.
 * @param result  Pointer to a buffer to hold the result.
 * @return Zero on success, or -1 if the string is incorrectly formatted.
 */
int str2cid(const char *s, struct ClockIdentity *result);

/**
 * Scan a string containing a port identity and convert it into binary form.
 *
 * @param s       String in human readable form.
 * @param result  Pointer to a buffer to hold the result.
 * @return Zero on success, or -1 if the string is incorrectly formatted.
 */
int str2pid(const char *s, struct PortIdentity *result);

int generate_clock_identity(struct ClockIdentity *ci, const char *name);

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
 * Values returned by get_ranged_*().
 */
enum parser_result {
	PARSED_OK,
	NOT_PARSED,
	BAD_VALUE,
	MALFORMED,
	OUT_OF_RANGE,
};

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

/**
 * Setup a handler for terminating signals (SIGINT, SIGQUIT, SIGTERM).
 *
 * @return       0 on success, -1 on error.
 */
int handle_term_signals(void);

/**
 * Check if a terminating signal was received.
 *
 * @return       1 if no terminating signal was received, 0 otherwise.
 */
int is_running(void);

/**
 * Allocate memory. This is a malloc() wrapper that terminates the process when
 * the allocation fails.
 *
 * @param size      Size of the block. Must be larger than 0.
 * @return          Pointer to the allocated memory.
 */
void *xmalloc(size_t size);

/**
 * Allocate and clear an array. This is a calloc() wrapper that terminates the
 * process when the allocation fails.
 *
 * @param nmemb     Number of elements. Must be larger than 0.
 * @param size      Size of the element. Must be larger than 0.
 * @return          Pointer to the allocated memory.
 */
void *xcalloc(size_t nmemb, size_t size);

/**
 * Reallocate memory. This is a realloc() wrapper that terminates the process
 * when the allocation fails.
 *
 * @param size      Size of the block. Must be larger than 0.
 * @return          Pointer to the allocated memory.
 */
void *xrealloc(void *ptr, size_t size);

/**
 * Duplicate a string. This is a strdup() wrapper that terminates the process
 * when the allocation fails.
 *
 * @param s         String that should be duplicated.
 * @return          Pointer to the duplicated string.
 */
char *xstrdup(const char *s);

/**
 * Get an allocated and formatted string. This is a wrapper around asprintf()
 * that terminates the process on errors.
 *
 * @param format    printf() format string.
 * @param ...       printf() arguments.
 * @return          Pointer to the allocated string.
 */
#ifdef __GNUC__
__attribute__ ((format (printf, 1, 2)))
#endif
char *string_newf(const char *format, ...);

/**
 * Reallocate a string and append another string to it. The process is
 * terminated when the allocation fails.
 *
 * @param s         String that should be extended.
 * @param str       String appended to s.
 */
void string_append(char **s, const char *str);
#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
#endif
/**
 * Reallocate a string and append a formatted string to it. The process is
 * terminated when the allocation fails.
 *
 * @param s         String that should be extended.
 * @param format    printf() format string.
 * @param ...       printf() arguments.
 */
void string_appendf(char **s, const char *format, ...);

/**
 * Get an empty array of pointers terminated by NULL. The process is terminated
 * when the allocation fails.
 *
 * @return          Pointer to the allocated array.
 */
void **parray_new(void);

/**
 * Append pointer to a NULL-terminated pointer array. The array is reallocated
 * in exponentially increasing sizes. The process is terminated when the
 * allocation fails.
 *
 * @param a         Pointer to pointer array.
 * @param p         Pointer appended to the array.
 */
void parray_append(void ***a, void *p);


/**
 * Append pointers to a NULL-terminated pointer array. The array is reallocated
 * in exponentially increasing sizes. The process is terminated when the
 * allocation fails.
 *
 * @param a         Pointer to pointer array.
 * @param ...       NULL-terminated list of pointers.
 */
void parray_extend(void ***a, ...);

/**
 * Check if enough time has passed to implement a simple rate limiting.
 *
 * @param interval  Minimum interval between two calls returning 0 (in seconds).
 * @param last      Time of the last call that returned 0, input/output.
 * @return          1 when rate limited, 0 otherwise.
 */
int rate_limited(int interval, time_t *last);

#endif
