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

#include <sys/queue.h>

#include "ds.h"
#include "dm.h"
#include "filter.h"
#include "transport.h"
#include "servo.h"
#include "sk.h"

#define MAX_IFNAME_SIZE 108 /* = UNIX_PATH_MAX */

/** Defines a network interface, with PTP options. */
struct interface {
	STAILQ_ENTRY(interface) list;
	char name[MAX_IFNAME_SIZE + 1];
	enum delay_mechanism dm;
	enum transport_type transport;
	struct port_defaults pod;
	struct sk_ts_info ts_info;
	enum filter_type delay_filter;
	int delay_filter_length;
	int boundary_clock_jbod;
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
	STAILQ_HEAD(interfaces_head, interface) interfaces;

	enum timestamp_type timestamping;
	enum transport_type transport;
	enum delay_mechanism dm;

	struct default_ds dds;
	struct port_defaults pod;
	int *assume_two_step;
	int *tx_timestamp_timeout;
	int *check_fup_sync;

	enum servo_type clock_servo;

	double *step_threshold;
	double *first_step_threshold;
	int *max_frequency;

	double *pi_proportional_const;
	double *pi_integral_const;
	double *pi_proportional_scale;
	double *pi_proportional_exponent;
	double *pi_proportional_norm_max;
	double *pi_integral_scale;
	double *pi_integral_exponent;
	double *pi_integral_norm_max;
	int *ntpshm_segment;

	unsigned char *ptp_dst_mac;
	unsigned char *p2p_dst_mac;
	unsigned char *udp6_scope;
	char *uds_address;

	int print_level;
	int use_syslog;
	int verbose;
};

int config_read(char *name, struct config *cfg);
struct interface *config_create_interface(char *name, struct config *cfg);
void config_init_interface(struct interface *iface, struct config *cfg);
void config_destroy(struct config *cfg);

#endif
