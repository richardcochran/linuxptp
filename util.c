/**
 * @file util.c
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
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "print.h"
#include "sk.h"
#include "util.h"

#define NS_PER_SEC 1000000000LL
#define NS_PER_HOUR (3600 * NS_PER_SEC)
#define NS_PER_DAY (24 * NS_PER_HOUR)

static int running = 1;

const char *ps_str[] = {
	"NONE",
	"INITIALIZING",
	"FAULTY",
	"DISABLED",
	"LISTENING",
	"PRE_MASTER",
	"MASTER",
	"PASSIVE",
	"UNCALIBRATED",
	"SLAVE",
	"GRAND_MASTER",
};

const char *ev_str[] = {
	"NONE",
	"POWERUP",
	"INITIALIZE",
	"DESIGNATED_ENABLED",
	"DESIGNATED_DISABLED",
	"FAULT_CLEARED",
	"FAULT_DETECTED",
	"STATE_DECISION_EVENT",
	"QUALIFICATION_TIMEOUT_EXPIRES",
	"ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES",
	"SYNCHRONIZATION_FAULT",
	"MASTER_CLOCK_SELECTED",
	"RS_MASTER",
	"RS_GRAND_MASTER",
	"RS_SLAVE",
	"RS_PASSIVE",
};

char *cid2str(struct ClockIdentity *id)
{
	static char buf[64];
	unsigned char *ptr = id->id;
	snprintf(buf, sizeof(buf), "%02x%02x%02x.%02x%02x.%02x%02x%02x",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7]);
	return buf;
}

char *pid2str(struct PortIdentity *id)
{
	static char buf[64];
	unsigned char *ptr = id->clockIdentity.id;
	snprintf(buf, sizeof(buf), "%02x%02x%02x.%02x%02x.%02x%02x%02x-%hu",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7],
		 id->portNumber);
	return buf;
}

int str2pid(const char *s, struct PortIdentity *result)
{
	struct PortIdentity pid;
	unsigned char *ptr = pid.clockIdentity.id;
	int c;
	c = sscanf(s, " %02hhx%02hhx%02hhx.%02hhx%02hhx.%02hhx%02hhx%02hhx-%hu",
		   &ptr[0], &ptr[1], &ptr[2], &ptr[3],
		   &ptr[4], &ptr[5], &ptr[6], &ptr[7],
		   &pid.portNumber);
	if (c == 9) {
		*result = pid;
		return 0;
	}
	return -1;
}

int generate_clock_identity(struct ClockIdentity *ci, const char *name)
{
	struct address addr;

	if (sk_interface_macaddr(name, &addr))
		return -1;
	ci->id[0] = addr.sa.sa_data[0];
	ci->id[1] = addr.sa.sa_data[1];
	ci->id[2] = addr.sa.sa_data[2];
	ci->id[3] = 0xFF;
	ci->id[4] = 0xFE;
	ci->id[5] = addr.sa.sa_data[3];
	ci->id[6] = addr.sa.sa_data[4];
	ci->id[7] = addr.sa.sa_data[5];
	return 0;
}

/* Naive count of utf8 symbols. Doesn't detect invalid UTF-8 and
 * probably doesn't count combining characters correctly. */
static size_t strlen_utf8(const Octet *s)
{
	size_t len = 0;
	char c;
	while ((c = *(s++))) {
		if ((c & 0xC0) != 0x80)
			len++;
	}
	return len;
}

int static_ptp_text_copy(struct static_ptp_text *dst, const struct PTPText *src)
{
	int len = src->length;
	if (dst->max_symbols > 0 && strlen_utf8(src->text) > dst->max_symbols)
		return -1;
	dst->length = len;
	memcpy(dst->text, src->text, len);
	dst->text[len] = '\0';
	return 0;
}

void ptp_text_copy(struct PTPText *dst, const struct static_ptp_text *src)
{
	dst->length = src->length;
	memcpy(dst->text, src->text, src->length);
}

int ptp_text_set(struct PTPText *dst, const char *src)
{
	size_t len;
	if (src) {
		len = strlen(src);
		if (len > MAX_PTP_OCTETS)
			return -1;
		dst->length = len;
		memcpy(dst->text, src, len);
	} else {
		dst->length = 0;
	}
	return 0;
}

int static_ptp_text_set(struct static_ptp_text *dst, const char *src)
{
	int len = strlen(src);
	if (len > MAX_PTP_OCTETS)
		return -1;
	if (dst->max_symbols > 0 && strlen_utf8((Octet *) src) > dst->max_symbols)
		return -1;
	dst->length = len;
	memcpy(dst->text, src, len);
	dst->text[len] = '\0';
	return 0;
}

int is_utc_ambiguous(uint64_t ts)
{
	/* The Linux kernel inserts leap second by stepping the clock backwards
	   at 0:00 UTC, the last second before midnight is played twice. */
	if (NS_PER_DAY - ts % NS_PER_DAY <= NS_PER_SEC)
		return 1;
	return 0;
}

int leap_second_status(uint64_t ts, int leap_set, int *leap, int *utc_offset)
{
	int leap_status = leap_set;

	/* The leap bits obtained by PTP should be set at most 12 hours before
	   midnight and unset at most 2 announce intervals after midnight.
	   Split updates which are too early and which are too late at 6 hours
	   after midnight. */
	if (ts % NS_PER_DAY > 6 * NS_PER_HOUR) {
		if (!leap_status)
			leap_status = *leap;
	} else {
		if (leap_status)
			leap_status = 0;
	}

	/* Fix early or late update of leap and utc_offset. */
	if (!*leap && leap_status) {
		*utc_offset -= leap_status;
		*leap = leap_status;
	} else if (*leap && !leap_status) {
		*utc_offset += *leap;
		*leap = leap_status;
	}

	return leap_status;
}

enum parser_result get_ranged_int(const char *str_val, int *result,
				  int min, int max)
{
	long parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtol(str_val, &endptr, 0);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

enum parser_result get_ranged_uint(const char *str_val, unsigned int *result,
				   unsigned int min, unsigned int max)
{
	unsigned long parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtoul(str_val, &endptr, 0);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

enum parser_result get_ranged_double(const char *str_val, double *result,
				     double min, double max)
{
	double parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtod(str_val, &endptr);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

int get_arg_val_i(int op, const char *optarg, int *val, int min, int max)
{
	enum parser_result r;
	r = get_ranged_int(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %d to %d\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

int get_arg_val_ui(int op, const char *optarg, unsigned int *val,
		   unsigned int min, unsigned int max)
{
	enum parser_result r;
	r = get_ranged_uint(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %u to %u\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

int get_arg_val_d(int op, const char *optarg, double *val,
		  double min, double max)
{
	enum parser_result r;
	r = get_ranged_double(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %e to %e\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

static void handle_int_quit_term(int s)
{
	running = 0;
}

int handle_term_signals(void)
{
	if (SIG_ERR == signal(SIGINT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGINT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGQUIT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGQUIT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGTERM, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGTERM\n");
		return -1;
	}
	return 0;
}

int is_running(void)
{
	return running;
}

char *string_newf(const char *format, ...)
{
	va_list ap;
	char *s;

	va_start(ap, format);
	if (vasprintf(&s, format, ap) < 0)
		s = NULL;
	va_end(ap);

	return s;
}

void string_append(char **s, const char *str)
{
	size_t len1, len2;

	len1 = strlen(*s);
	len2 = strlen(str);
	*s = realloc(*s, len1 + len2 + 1);
	if (*s)
		memcpy((*s) + len1, str, len2 + 1);
}

void string_appendf(char **s, const char *format, ...)
{
	va_list ap;
	size_t len1, len2;
	char *s2;

	len1 = strlen(*s);

	va_start(ap, format);
	len2 = vasprintf(&s2, format, ap);
	va_end(ap);

	if (len2 < 0) {
		*s = NULL;
		return;
	}

	*s = realloc(*s, len1 + len2 + 1);
	if (*s)
		memcpy((*s) + len1, s2, len2 + 1);
	free(s2);
}

void **parray_new(void)
{
	void **a = malloc(sizeof(*a));

	if (a)
		*a = NULL;
	return a;
}

void parray_append(void ***a, void *p)
{
	parray_extend(a, p, NULL);
}

void parray_extend(void ***a, ...)
{
	va_list ap;
	int ilen, len, alloced;
	void *p;

	for (len = 0; (*a)[len]; len++)
		;
	len++;

	va_start(ap, a);
	for (ilen = 0; va_arg(ap, void *); ilen++)
		;
	va_end(ap);

	/* Reallocate in exponentially increasing sizes. */
	for (alloced = 1; alloced < len; alloced <<= 1)
		;
	if (alloced < len + ilen) {
		while (alloced < len + ilen)
			alloced *= 2;
		*a = realloc(*a, alloced * sizeof **a);
		if (!*a)
			return;
	}

	va_start(ap, a);
	while ((p = va_arg(ap, void *)))
		(*a)[len++ - 1] = p;
	va_end(ap);
	(*a)[len - 1] = NULL;
}
