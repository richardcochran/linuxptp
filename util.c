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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sk.h"
#include "util.h"

#define NS_PER_SEC 1000000000LL
#define NS_PER_HOUR (3600 * NS_PER_SEC)
#define NS_PER_DAY (24 * NS_PER_HOUR)

char *ps_str[] = {
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

char *ev_str[] = {
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

int generate_clock_identity(struct ClockIdentity *ci, char *name)
{
	unsigned char mac[6];
	if (sk_interface_macaddr(name, mac, sizeof(mac)))
		return -1;
	ci->id[0] = mac[0];
	ci->id[1] = mac[1];
	ci->id[2] = mac[2];
	ci->id[3] = 0xFF;
	ci->id[4] = 0xFE;
	ci->id[5] = mac[3];
	ci->id[6] = mac[4];
	ci->id[7] = mac[5];
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
