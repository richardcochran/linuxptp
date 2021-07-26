/**
 * @file lstab.c
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "lstab.h"

/*
 * Keep a history of the TAI - UTC offset in a lookup table.
 *
 * Each entry gives the NTP time when a new TAI offset came into
 * effect. This is always the second immediately after a leap second.
 *
 * The size of the table is the number of entries from the NIST table,
 * plus room for two hundred more entries to be added at run time.
 * Since there can be at most two leap seconds per year, this allows
 * for at least one hundred years.
 *
 * The table data are available from
 *
 * https://www.ietf.org/timezones/data/leap-seconds.list
 *
 * ftp://ftp.nist.gov/pub/time/leap-seconds.list
 *
 * When updating this table, do not forget to set N_HISTORICAL_LEAPS
 * and the expiration date.
 */

#define BASE_TAI_OFFSET		10
#define N_HISTORICAL_LEAPS	28
#define N_LEAPS			(N_HISTORICAL_LEAPS + 200)
#define NTP_UTC_OFFSET		2208988800ULL

struct epoch_marker {
	int offset;	/* TAI - UTC offset of epoch */
	uint64_t ntp;	/* NTP time of epoch */
	uint64_t tai;	/* TAI time of epoch */
	uint64_t utc;	/* UTC time of epoch */
};

struct lstab {
	struct epoch_marker lstab[N_LEAPS];
	uint64_t expiration_utc;
	int length;
};

static const uint64_t expiration_date_ntp = 3849638400ULL; /* 28 December 2021 */

static const uint64_t offset_table[N_LEAPS * 2] = {
	2272060800ULL,	10,	/* 1 Jan 1972 */
	2287785600ULL,	11,	/* 1 Jul 1972 */
	2303683200ULL,	12,	/* 1 Jan 1973 */
	2335219200ULL,	13,	/* 1 Jan 1974 */
	2366755200ULL,	14,	/* 1 Jan 1975 */
	2398291200ULL,	15,	/* 1 Jan 1976 */
	2429913600ULL,	16,	/* 1 Jan 1977 */
	2461449600ULL,	17,	/* 1 Jan 1978 */
	2492985600ULL,	18,	/* 1 Jan 1979 */
	2524521600ULL,	19,	/* 1 Jan 1980 */
	2571782400ULL,	20,	/* 1 Jul 1981 */
	2603318400ULL,	21,	/* 1 Jul 1982 */
	2634854400ULL,	22,	/* 1 Jul 1983 */
	2698012800ULL,	23,	/* 1 Jul 1985 */
	2776982400ULL,	24,	/* 1 Jan 1988 */
	2840140800ULL,	25,	/* 1 Jan 1990 */
	2871676800ULL,	26,	/* 1 Jan 1991 */
	2918937600ULL,	27,	/* 1 Jul 1992 */
	2950473600ULL,	28,	/* 1 Jul 1993 */
	2982009600ULL,	29,	/* 1 Jul 1994 */
	3029443200ULL,	30,	/* 1 Jan 1996 */
	3076704000ULL,	31,	/* 1 Jul 1997 */
	3124137600ULL,	32,	/* 1 Jan 1999 */
	3345062400ULL,	33,	/* 1 Jan 2006 */
	3439756800ULL,	34,	/* 1 Jan 2009 */
	3550089600ULL,	35,	/* 1 Jul 2012 */
	3644697600ULL,	36,	/* 1 Jul 2015 */
	3692217600ULL,	37,	/* 1 Jan 2017 */
};

static void epoch_marker_init(struct epoch_marker *ls, uint64_t val, int offset)
{
	ls->ntp = val;
	ls->utc = val - NTP_UTC_OFFSET;
	ls->tai = val - NTP_UTC_OFFSET + offset;
	ls->offset = offset;
}

static void lstab_init(struct lstab *lstab)
{
	struct epoch_marker *ls;
	uint64_t offset, val;
	int i;

	for (i = 0; i < N_HISTORICAL_LEAPS; i++) {
		ls = lstab->lstab + i;
		val = offset_table[2 * i];
		offset = offset_table[2 * i + 1];
		epoch_marker_init(ls, val, offset);
	}
	lstab->expiration_utc = expiration_date_ntp - NTP_UTC_OFFSET;
	lstab->length = i;
}

void lstab_print(struct lstab *lstab, FILE *fp)
{
	int i, len = lstab->length;

	fprintf(fp, "%3s%12s%12s%12s%4s\n", "idx", "NTP", "TAI", "UTC", "OFF");
	for (i = 0; i < len; i++) {
		fprintf(fp, "%3d" "%12" PRIu64 "%12" PRIu64 "%12" PRIu64 "%4d\n", i,
			lstab->lstab[i].ntp, lstab->lstab[i].tai,
			lstab->lstab[i].utc, lstab->lstab[i].offset);
	}
}

static int lstab_read(struct lstab *lstab, const char *name)
{
	uint64_t expiration, val;
	struct epoch_marker *ls;
	int index = 0, offset;
	char buf[1024];
	FILE *fp;

	fp = fopen(name, "r");
	if (!fp) {
		fprintf(stderr, "failed to open '%s' for reading: %m\n", name);
		return -1;
	}
	while (1) {
		if (!fgets(buf, sizeof(buf), fp)) {
			break;
		}
		if (1 == sscanf(buf, "#@ %" PRIu64, &expiration)) {
			lstab->expiration_utc = expiration - NTP_UTC_OFFSET;
			continue;
		}
		if (2 == sscanf(buf, "%" PRIu64 " %d", &val, &offset)) {
			ls = lstab->lstab + index;
			epoch_marker_init(ls, val, offset);
			index++;
		}
	}
	fclose(fp);
	if (!lstab->expiration_utc) {
		fprintf(stderr, "missing expiration date in '%s'\n", name);
		return -1;
	}
	lstab->length = index;

	return 0;
}

struct lstab *lstab_create(const char *filename)
{
	struct lstab *lstab = calloc(1, sizeof(*lstab));

	if (!lstab) {
		return NULL;
	}
	if (filename && filename[0]) {
		if (lstab_read(lstab, filename)) {
			free(lstab);
			return NULL;
		}
	} else {
		lstab_init(lstab);
	}
	return lstab;
}

void lstab_destroy(struct lstab *lstab)
{
	free(lstab);
}

enum lstab_result lstab_utc2tai(struct lstab *lstab, uint64_t utctime,
				int *tai_offset)
{
	int epoch = -1, index, next;

	if (utctime > lstab->expiration_utc) {
		return LSTAB_UNKNOWN;
	}

	for (index = lstab->length - 1; index > -1; index--) {
		if (utctime >= lstab->lstab[index].utc) {
			epoch = index;
			break;
		}
	}

	if (epoch == -1) {
		return LSTAB_UNKNOWN;
	}

	*tai_offset = lstab->lstab[epoch].offset;
	next = epoch + 1;

	if (next < lstab->length && utctime == lstab->lstab[next].utc - 1) {
		return LSTAB_AMBIGUOUS;
	}
	return LSTAB_OK;
}
