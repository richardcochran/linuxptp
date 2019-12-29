/**
 * @file ts2phc_nmea_master.h
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_NMEA_MASTER_H
#define HAVE_TS2PHC_NMEA_MASTER_H

#include "ts2phc_master.h"

struct ts2phc_master *ts2phc_nmea_master_create(struct config *cfg,
						const char *dev);
#endif
