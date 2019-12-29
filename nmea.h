/**
 * @file nmea.h
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_NMEA_H
#define HAVE_NMEA_H

#include <stdbool.h>
#include <time.h>

/** Opaque type. */
struct nmea_parser;

struct nmea_rmc {
	struct timespec ts;
	bool fix_valid;
};

/**
 * Parses NMEA RMC sentences out of a given buffer.
 * @param np		Pointer obtained via nmea_parser_create().
 * @param buf		Pointer to the data to be parsed.
 * @param buflen	Length of 'buf' in bytes.
 * @param rmc		Pointer to hold the result.
 * @param parsed	Returns the number of bytes parsed, possibly less than buflen.
 * @return		Zero on success, non-zero otherwise.
 */
int nmea_parse(struct nmea_parser *np, const char *buf, int buflen,
	       struct nmea_rmc *rmc, int *parsed);

/**
 * Creates an instance of an NMEA parser.
 * @return	Pointer to a new instance on success, NULL otherwise.
 */
struct nmea_parser *nmea_parser_create(void);

/**
 * Destroys an NMEA parser instance.
 * @param np	Pointer obtained via nmea_parser_create().
 */
void nmea_parser_destroy(struct nmea_parser *np);

#endif
