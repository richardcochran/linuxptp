/**
 * @file ts2phc_pps_sink.h
 * @brief Utility program to synchronize the PHC clock to external events
 * @note Copyright (C) 2019 Balint Ferencz <fernya@sch.bme.hu>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_TS2PHC_PPS_SINK_H
#define HAVE_TS2PHC_PPS_SINK_H

#include "ts2phc.h"

struct ts2phc_private;

int ts2phc_pps_sink_add(struct ts2phc_private *priv, const char *name);

int ts2phc_pps_sinks_init(struct ts2phc_private *priv);

void ts2phc_pps_sink_cleanup(struct ts2phc_private *priv);

int ts2phc_pps_sink_poll(struct ts2phc_private *priv);

#endif
