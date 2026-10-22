/**
 * @file fine_ts.h
 * @brief Optional provider of sub-nanosecond time stamp corrections.
 * @note Copyright (C) 2026 Liquid Instruments Pty Ltd
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
#ifndef HAVE_FINE_TS_H
#define HAVE_FINE_TS_H

#include <stdint.h>

#include "config.h"
#include "ddt.h"
#include "tmv.h"

/*
 * The messages are in host byte order, including the fields copied from
 * the PTP header, so the transmit path must read the header before
 * msg_pre_send() swaps it.
 */
#define FINE_TS_MAGIC		0x46545331 /* "FTS1" */
#define FINE_TS_VERSION		1

enum fine_ts_direction {
	FINE_TS_INGRESS = 0,
	FINE_TS_EGRESS  = 1,
};

enum fine_ts_status {
	FINE_TS_OK = 0,
	FINE_TS_UNKNOWN = 1,
};

/*
 * The event is keyed by interface, direction and message identity.  The
 * whole nanoseconds are there for the provider to cross check, not as
 * the key.
 */
struct fine_ts_request {
	uint32_t	magic;
	uint8_t		version;
	uint8_t		direction;	/**< enum fine_ts_direction */
	uint8_t		message_type;	/**< PTP messageType nibble */
	uint8_t		reserved1;
	uint32_t	ifindex;
	uint32_t	sequence_id;	/**< PTP sequenceId */
	struct PortIdentity port_identity;
	uint16_t	reserved2;
	int64_t		seconds;
	uint32_t	nanoseconds;
	uint32_t	xid;		/**< transaction identifier */
} PACKED;

struct fine_ts_reply {
	uint32_t	magic;
	uint8_t		version;
	uint8_t		status;		/**< enum fine_ts_status */
	uint16_t	reserved1;
	uint32_t	xid;		/**< echo of the request */
	int32_t		fraction;	/**< to add, in units of 2^-16 ns */
} PACKED;

/**
 * Connect to the configured provider, if any.
 * @param cfg  The configuration database.
 * @return     Zero on success or when none is configured, -1 on error.
 */
int fine_ts_init(struct config *cfg);

void fine_ts_cleanup(void);

/**
 * Add the provider's fraction to an event time stamp.  The time stamp
 * is left unchanged if there is no provider or no answer.
 * @param ifindex   Index of the interface.
 * @param dir       Reception or transmission.
 * @param msg_type  PTP messageType.
 * @param seqid     PTP sequenceId, in host byte order.
 * @param pid       Source port identity, in host byte order.
 * @param ts        The time stamp, updated in place.
 */
void fine_ts_apply(unsigned int ifindex, enum fine_ts_direction dir,
		   uint8_t msg_type, uint16_t seqid,
		   const struct PortIdentity *pid, tmv_t *ts);

#endif
