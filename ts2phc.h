/**
 * @file ts2phc.h
 * @brief Structure definitions for ts2phc
 * @note Copyright 2020-2022 Vladimir Oltean <olteanv@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_H
#define HAVE_TS2PHC_H

#include "ts2phc_pps_source.h"
#include "ts2phc_pps_sink.h"

struct ts2phc_sink_array;

struct ts2phc_private {
	struct ts2phc_pps_source *src;
	STAILQ_HEAD(sink_ifaces_head, ts2phc_pps_sink) sinks;
	unsigned int n_sinks;
	struct ts2phc_sink_array *polling_array;
	struct config *cfg;
};

#endif
