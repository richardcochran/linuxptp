/**
 * @file nmea.c
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nmea.h"
#include "print.h"

#define NMEA_CHAR_MIN	' '
#define NMEA_CHAR_MAX	'~'
#define NMEA_MAX_LENGTH	256

enum nmea_state {
	NMEA_IDLE,
	NMEA_HAVE_DOLLAR,
	NMEA_HAVE_STARTG,
	NMEA_HAVE_STARTX,
	NMEA_HAVE_BODY,
	NMEA_HAVE_CSUMA,
	NMEA_HAVE_CSUM_MSB,
	NMEA_HAVE_CSUM_LSB,
	NMEA_HAVE_PENULTIMATE,
};

struct nmea_parser {
	char sentence[NMEA_MAX_LENGTH + 1];
	char payload_checksum[3];
	enum nmea_state state;
	uint8_t checksum;
	int offset;
};

static void nmea_reset(struct nmea_parser *np);

static void nmea_accumulate(struct nmea_parser *np, char c)
{
	if (c < NMEA_CHAR_MIN || c > NMEA_CHAR_MAX) {
		nmea_reset(np);
		return;
	}
	if (np->offset == NMEA_MAX_LENGTH) {
		nmea_reset(np);
	}
	np->sentence[np->offset++] = c;
	np->checksum ^= c;
}

static int nmea_parse_symbol(struct nmea_parser *np, char c)
{
	switch (np->state) {
	case NMEA_IDLE:
		if (c == '$') {
			np->state = NMEA_HAVE_DOLLAR;
		}
		break;
	case NMEA_HAVE_DOLLAR:
		if (c == 'G') {
			np->state = NMEA_HAVE_STARTG;
			nmea_accumulate(np, c);
		} else {
			nmea_reset(np);
		}
		break;
	case NMEA_HAVE_STARTG:
		np->state = NMEA_HAVE_STARTX;
		nmea_accumulate(np, c);
		break;
	case NMEA_HAVE_STARTX:
		np->state = NMEA_HAVE_BODY;
		nmea_accumulate(np, c);
		break;
	case NMEA_HAVE_BODY:
		if (c == '*') {
			np->state = NMEA_HAVE_CSUMA;
		} else {
			nmea_accumulate(np, c);
		}
		break;
	case NMEA_HAVE_CSUMA:
		np->state = NMEA_HAVE_CSUM_MSB;
		np->payload_checksum[0] = c;
		break;
	case NMEA_HAVE_CSUM_MSB:
		np->state = NMEA_HAVE_CSUM_LSB;
		np->payload_checksum[1] = c;
		break;
	case NMEA_HAVE_CSUM_LSB:
		if (c == '\n') {
			/*skip the CR*/
			return 0;
		}
		if (c == '\r') {
			np->state = NMEA_HAVE_PENULTIMATE;
		} else {
			nmea_reset(np);
		}
		break;
	case NMEA_HAVE_PENULTIMATE:
		if (c == '\n') {
			return 0;
		}
		nmea_reset(np);
		break;
	}
	return -1;
}

static void nmea_reset(struct nmea_parser *np)
{
	memset(np, 0, sizeof(*np));
}

static int nmea_scan_rmc(struct nmea_parser *np, struct nmea_rmc *result)
{
	int cnt, i, msec = 0;
	char *ptr, status;
	uint8_t checksum;
	struct tm tm;

	pr_debug("nmea sentence: %s", np->sentence);
	cnt = sscanf(np->payload_checksum, "%02hhx", &checksum);
	if (cnt != 1) {
		return -1;
	}
	if (checksum != np->checksum) {
		pr_err("checksum mismatch 0x%02hhx != 0x%02hhx on %s",
		       checksum, np->checksum, np->sentence);
		return -1;
	}
	cnt = sscanf(np->sentence,
		     "G%*cRMC,%2d%2d%2d.%d,%c",
		     &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &msec, &status);
	if (cnt != 5) {
		cnt = sscanf(np->sentence,
			     "G%*cRMC,%2d%2d%2d,%c",
			     &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &status);
		if (cnt != 4) {
			return -1;
		}
	}
	ptr = np->sentence;
	for (i = 0; i < 9; i++) {
		ptr = strchr(ptr, ',');
		if (!ptr) {
			return -1;
		}
		ptr++;
	}
	cnt = sscanf(ptr, "%2d%2d%2d", &tm.tm_mday, &tm.tm_mon, &tm.tm_year);
	if (cnt != 3) {
		return -1;
	}
	/* Convert an inserted leap second to ambiguous 23:59:59 */
	if (tm.tm_sec == 60)
		tm.tm_sec = 59;
	tm.tm_year += 100;
	tm.tm_mon--;
	tm.tm_isdst = 0;
	result->ts.tv_sec = mktime(&tm);
	result->ts.tv_nsec = msec * 1000000UL;
	result->fix_valid = status == 'A' ? true : false;
	return 0;
}

int nmea_parse(struct nmea_parser *np, const char *ptr, int buflen,
	       struct nmea_rmc *result, int *parsed)
{
	int count = 0;
	while (buflen) {
		if (!nmea_parse_symbol(np, *ptr)) {
			if (!nmea_scan_rmc(np, result)) {
				nmea_reset(np);
				*parsed = count + 1;
				return 0;
			}
			nmea_reset(np);
		}
		buflen--;
		count++;
		ptr++;
	}
	*parsed = count;
	return -1;
}

struct nmea_parser *nmea_parser_create(void)
{
	struct nmea_parser *np;
	np = malloc(sizeof(*np));
	if (!np) {
		return NULL;
	}
	nmea_reset(np);
	/* Ensure that mktime(3) returns a value in the UTC time scale. */
	setenv("TZ", "UTC", 1);
	return np;
}

void nmea_parser_destroy(struct nmea_parser *np)
{
	free(np);
}
