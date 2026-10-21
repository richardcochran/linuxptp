/**
 * @file l1_state.h
 * @brief Optional provider of layer-1 syntonization state.
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
#ifndef HAVE_L1_STATE_H
#define HAVE_L1_STATE_H

#include <stdint.h>

#include "config.h"
#include "ddt.h"

#define L1_STATE_MAGIC		0x4C315331 /* "L1S1" */
#define L1_STATE_VERSION	1

enum l1_state_command {
	L1_CMD_ENABLE = 0,	/**< apply the relationship, idempotent */
	L1_CMD_DISABLE = 1,	/**< release it */
	L1_CMD_QUERY = 2,	/**< report the state of the interface */
};

/* Flags of a reply to L1_CMD_QUERY. */
#define L1_STATE_TX_COHERENT	(1 << 0)
#define L1_STATE_RX_COHERENT	(1 << 1)
#define L1_STATE_CONGRUENT	(1 << 2)
#define L1_STATE_VALID		(1 << 3)	/**< clear: cannot tell */

struct l1_state_request {
	uint32_t	magic;
	uint8_t		version;
	uint8_t		command;	/**< enum l1_state_command */
	uint16_t	reserved;
	uint32_t	ifindex;
	uint32_t	xid;		/**< transaction identifier */
} PACKED;

struct l1_state_reply {
	uint32_t	magic;
	uint8_t		version;
	uint8_t		flags;		/**< L1_STATE_* */
	uint16_t	reserved;
	uint32_t	xid;		/**< echo of the request */
} PACKED;

struct l1_state {
	Boolean	isTxCoherent;
	Boolean	isRxCoherent;
	Boolean	isCongruent;
};

/**
 * Connect to the configured provider, if any.
 * @param cfg  The configuration database.
 * @return     Zero on success or when none is configured, -1 on error.
 */
int l1_state_init(struct config *cfg);

void l1_state_cleanup(void);

/**
 * Ask the provider to apply or release the relationship on an interface.
 * There is no reply; does nothing without a provider.
 */
void l1_state_command(unsigned int ifindex, enum l1_state_command cmd);

/**
 * Ask the provider about an interface.  This fails closed: without a
 * valid answer every member of @a st is FALSE.
 */
void l1_state_query(unsigned int ifindex, struct l1_state *st);

#endif
