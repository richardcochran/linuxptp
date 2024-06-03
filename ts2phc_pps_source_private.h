/**
 * @file ts2phc_pps_source_private.h
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_PPS_SOURCE_PRIVATE_H
#define HAVE_TS2PHC_PPS_SOURCE_PRIVATE_H

#include <stdint.h>
#include <time.h>

#include "contain.h"
#include "ts2phc_pps_source.h"

struct ts2phc_pps_source {
	enum ts2phc_pps_source_type type;
	void (*destroy)(struct ts2phc_pps_source *src);
	int (*getppstime)(struct ts2phc_pps_source *src, struct timespec *ts);
	struct ts2phc_clock *(*get_clock)(struct ts2phc_pps_source *src);
};

#endif
