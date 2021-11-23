/**
 * @file ts2phc_pps_source.h
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_PPS_SOURCE_H
#define HAVE_TS2PHC_PPS_SOURCE_H

#include <time.h>

struct config;

/**
 * Opaque type
 */
struct ts2phc_pps_source;

/**
 * Defines the available PPS sources.
 */
enum ts2phc_pps_source_type {
	TS2PHC_PPS_SOURCE_GENERIC,
	TS2PHC_PPS_SOURCE_NMEA,
	TS2PHC_PPS_SOURCE_PHC,
};

/**
 * Create a new instance of a PPS source.
 * @param cfg	Pointer to a valid configuration.
 * @param dev   Name of the source or NULL.
 * @param type	The type of the clock to create.
 * @return	A pointer to a new PPS source on success, NULL otherwise.
 */
struct ts2phc_pps_source *ts2phc_pps_source_create(struct config *cfg, const char *dev,
						   enum ts2phc_pps_source_type type);

/**
 * Destroy an instance of a PPS source.
 * @param src Pointer to a source obtained via @ref ts2phc_pps_source_create().
 */
void ts2phc_pps_source_destroy(struct ts2phc_pps_source *src);

/**
 * Returns the time on the PPS source device at which the most recent
 * PPS event was generated.
 * @param src    Pointer to a source obtained via @ref ts2phc_pps_source_create().
 * @param ts     Buffer to hold the time of the last PPS event.
 * @return       Zero if the reported time is valid, non-zero otherwise.
 */
int ts2phc_pps_source_getppstime(struct ts2phc_pps_source *src, struct timespec *ts);

#endif
