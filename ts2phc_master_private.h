/**
 * @file ts2phc_master_private.h
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_MASTER_PRIVATE_H
#define HAVE_TS2PHC_MASTER_PRIVATE_H

#include <stdint.h>
#include <time.h>

#include "contain.h"
#include "ts2phc_master.h"

struct ts2phc_master {
	void (*destroy)(struct ts2phc_master *ts2phc_master);
	int (*getppstime)(struct ts2phc_master *master, struct timespec *ts);
};

#endif
