/**
 * @file ts2phc_master.h
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_MASTER_H
#define HAVE_TS2PHC_MASTER_H

#include <time.h>

struct config;

/**
 * Opaque type
 */
struct ts2phc_master;

/**
 * Defines the available PPS master clocks.
 */
enum ts2phc_master_type {
	TS2PHC_MASTER_GENERIC,
	TS2PHC_MASTER_NMEA,
	TS2PHC_MASTER_PHC,
};

/**
 * Create a new instance of a PPS master clock.
 * @param cfg	Pointer to a valid configuration.
 * @param dev   Name of the master clock or NULL.
 * @param type	The type of the clock to create.
 * @return	A pointer to a new PPS master clock on success, NULL otherwise.
 */
struct ts2phc_master *ts2phc_master_create(struct config *cfg, const char *dev,
					   enum ts2phc_master_type type);

/**
 * Destroy an instance of a PPS master clock.
 * @param master Pointer to a master obtained via @ref ts2phc_master_create().
 */
void ts2phc_master_destroy(struct ts2phc_master *master);

/**
 * Returns the time on the PPS source device at which the most recent
 * PPS event was generated.
 * @param master Pointer to a master obtained via @ref ts2phc_master_create().
 * @param ts     Buffer to hold the time of the last PPS event.
 * @return       Zero if the reported time is valid, non-zero otherwise.
 */
int ts2phc_master_getppstime(struct ts2phc_master *master, struct timespec *ts);

#endif
