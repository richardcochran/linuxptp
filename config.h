/**
 * @file config.h
 * @brief Configuration file code
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H

#include "ds.h"
#include "dm.h"
#include "transport.h"
#include "servo.h"
#include "sk.h"

#define MAX_PORTS 8
#define MAX_IFNAME_SIZE 16

/** Defines a network interface, with PTP options. */
struct interface {
	char name[MAX_IFNAME_SIZE + 1];
	enum delay_mechanism dm;
	enum transport_type transport;
	struct port_defaults pod;
	struct sk_ts_info ts_info;
};

#define CFG_IGNORE_DM           (1 << 0)
#define CFG_IGNORE_TRANSPORT    (1 << 1)
#define CFG_IGNORE_TIMESTAMPING (1 << 2)
#define CFG_IGNORE_SLAVEONLY    (1 << 3)
#define CFG_IGNORE_PRINT_LEVEL  (1 << 4)
#define CFG_IGNORE_USE_SYSLOG   (1 << 5)
#define CFG_IGNORE_VERBOSE      (1 << 6)

struct config {
	/* configuration override */
	int cfg_ignore;

	/* configured interfaces */
	struct interface iface[MAX_PORTS];
	int nports;

	enum timestamp_type timestamping;
	enum transport_type transport;
	enum delay_mechanism dm;

	struct defaultDS dds;
	struct port_defaults pod;
	int *assume_two_step;
	int *tx_timestamp_retries;

	enum servo_type clock_servo;

	double *pi_proportional_const;
	double *pi_integral_const;
	double *pi_offset_const;

	unsigned char *ptp_dst_mac;
	unsigned char *p2p_dst_mac;

	int print_level;
	int use_syslog;
	int verbose;
};

int config_read(char *name, struct config *cfg);
int config_create_interface(char *name, struct config *cfg);

#endif
