/**
 * @file l1sync.h
 * @brief Layer-1 based synchronization performance enhancement, Annex L.
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
#ifndef HAVE_L1SYNC_H
#define HAVE_L1SYNC_H

#include <stddef.h>

#include "ddt.h"

/** States of Table L.1, with their on the wire values. */
enum l1sync_state {
	L1S_DISABLED     = 0x01,
	L1S_IDLE         = 0x02,
	L1S_LINK_ALIVE   = 0x03,
	L1S_CONFIG_MATCH = 0x04,
	L1S_L1_SYNC_UP   = 0x05,
};

/* Bits of the L1_SYNC TLV, Table L.3. */
#define L1SYNC_TCR	(1 << 0)	/**< txCoherentIsRequired */
#define L1SYNC_RCR	(1 << 1)	/**< rxCoherentIsRequired */
#define L1SYNC_CR	(1 << 2)	/**< congruentIsRequired */
#define L1SYNC_OPE	(1 << 3)	/**< optParamsEnabled */

#define L1SYNC_ITC	(1 << 0)	/**< isTxCoherent */
#define L1SYNC_IRC	(1 << 1)	/**< isRxCoherent */
#define L1SYNC_IC	(1 << 2)	/**< isCongruent */

#define L1SYNC_LEN_BASIC	2

struct l1sync_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         config;
	Octet         active;
} PACKED;

/*
 * L1SyncBasicPortDS, 8.2.23.  Also the L1SYNC_BASIC_PORT_DS_NP management
 * TLV: every member is one octet, so there is nothing to byte swap.
 */
struct l1sync_basic_port_ds {
	UInteger8    L1SyncEnabled;
	UInteger8    txCoherentIsRequired;
	UInteger8    rxCoherentIsRequired;
	UInteger8    congruentIsRequired;
	UInteger8    optParamsEnabled;
	Integer8     logL1SyncInterval;
	UInteger8    L1SyncReceiptTimeout;
	UInteger8    L1SyncLinkAlive;
	UInteger8    isTxCoherent;
	UInteger8    isRxCoherent;
	UInteger8    isCongruent;
	Enumeration8 L1SyncState;
	UInteger8    peerTxCoherentIsRequired;
	UInteger8    peerRxCoherentIsRequired;
	UInteger8    peerCongruentIsRequired;
	UInteger8    peerIsTxCoherent;
	UInteger8    peerIsRxCoherent;
	UInteger8    peerIsCongruent;
} PACKED;

/** Reset the dynamic members, including the peer ones, per L.5.1. */
void l1sync_reset_dynamic(struct l1sync_basic_port_ds *bds);

/** Reset the peer members of Table L.2, per L.5.1. */
void l1sync_reset_peer(struct l1sync_basic_port_ds *bds);

/** The CONFIG_OK variable of Table L.5. */
int l1sync_config_ok(const struct l1sync_basic_port_ds *bds);

/** The STATE_OK variable of Table L.5. */
int l1sync_state_ok(const struct l1sync_basic_port_ds *bds);

/**
 * Write the basic format of the L1_SYNC TLV.  The type and length are
 * left in host byte order.
 */
void l1sync_pack(struct l1sync_tlv *tlv,
		 const struct l1sync_basic_port_ds *bds);

/**
 * Store a received L1_SYNC TLV in the peer members.  A TLV longer than
 * the basic format is accepted and the rest ignored, per L.6.3.
 * @param tlv    The TLV, with type and length in host byte order.
 * @param avail  Octets readable at @a tlv.
 * @param bds    The data set to update.
 * @return       Zero on success, -1 if malformed, leaving @a bds alone.
 */
int l1sync_unpack(const struct TLV *tlv, size_t avail,
		  struct l1sync_basic_port_ds *bds);

const char *l1sync_state_name(Enumeration8 state);

#endif
