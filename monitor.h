/**
 * @file monitor.h
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_MONITOR_H
#define HAVE_MONITOR_H

#include "config.h"
#include "port.h"
#include "tmv.h"

struct monitor;

struct monitor *monitor_create(struct config *config, struct port *dst);

int monitor_delay(struct monitor *monitor, struct PortIdentity source_pid,
		  uint16_t seqid, tmv_t t3, tmv_t corr, tmv_t t4);

void monitor_destroy(struct monitor *monitor);

int monitor_sync(struct monitor *monitor, struct PortIdentity source_pid,
		 uint16_t seqid, tmv_t t1, tmv_t corr, tmv_t t2);

#endif
