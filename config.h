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

#define MAX_PORTS 8

/** Defines a network interface, with PTP options. */
struct interface {
	char *name;
	enum delay_mechanism dm;
	enum transport_type transport;
};

struct config {
	/* configured interfaces */
	struct interface iface[MAX_PORTS];
	int nports;

	struct defaultDS *dds;
	struct port_defaults *pod;
	int *assume_two_step;
	int *tx_timestamp_retries;
	int *rx_timestamp_l2only;
	double *pi_proportional_const;
	double *pi_integral_const;
	unsigned char *ptp_dst_mac;
	unsigned char *p2p_dst_mac;
};

int config_read(char *name, struct config *cfg);

#endif
