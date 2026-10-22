/**
 * @file l1sync_msg.c
 * @brief Codec for the L1_SYNC TLV and the data sets behind it.
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
#include "l1sync.h"
#include "tlv.h"

void l1sync_reset_dynamic(struct l1sync_basic_port_ds *bds)
{
	bds->L1SyncLinkAlive = FALSE;
	bds->isTxCoherent = FALSE;
	bds->isRxCoherent = FALSE;
	bds->isCongruent = FALSE;
	bds->L1SyncState = L1S_DISABLED;
	l1sync_reset_peer(bds);
}

void l1sync_reset_peer(struct l1sync_basic_port_ds *bds)
{
	bds->peerTxCoherentIsRequired = FALSE;
	bds->peerRxCoherentIsRequired = FALSE;
	bds->peerCongruentIsRequired = FALSE;
	bds->peerIsTxCoherent = FALSE;
	bds->peerIsRxCoherent = FALSE;
	bds->peerIsCongruent = FALSE;
}

int l1sync_config_ok(const struct l1sync_basic_port_ds *bds)
{
	return !bds->txCoherentIsRequired == !bds->peerTxCoherentIsRequired &&
	       !bds->rxCoherentIsRequired == !bds->peerRxCoherentIsRequired &&
	       !bds->congruentIsRequired == !bds->peerCongruentIsRequired;
}

int l1sync_state_ok(const struct l1sync_basic_port_ds *bds)
{
	return (!bds->txCoherentIsRequired ||
		(bds->isTxCoherent && bds->peerIsTxCoherent)) &&
	       (!bds->rxCoherentIsRequired ||
		(bds->isRxCoherent && bds->peerIsRxCoherent)) &&
	       (!bds->congruentIsRequired ||
		(bds->isCongruent && bds->peerIsCongruent));
}

void l1sync_pack(struct l1sync_tlv *tlv,
		 const struct l1sync_basic_port_ds *bds)
{
	Octet config = 0, active = 0;

	if (bds->txCoherentIsRequired) {
		config |= L1SYNC_TCR;
	}
	if (bds->rxCoherentIsRequired) {
		config |= L1SYNC_RCR;
	}
	if (bds->congruentIsRequired) {
		config |= L1SYNC_CR;
	}
	if (bds->optParamsEnabled) {
		config |= L1SYNC_OPE;
	}
	if (bds->isTxCoherent) {
		active |= L1SYNC_ITC;
	}
	if (bds->isRxCoherent) {
		active |= L1SYNC_IRC;
	}
	if (bds->isCongruent) {
		active |= L1SYNC_IC;
	}

	tlv->type = TLV_L1_SYNC;
	tlv->length = L1SYNC_LEN_BASIC;
	tlv->config = config;
	tlv->active = active;
}

int l1sync_unpack(const struct TLV *tlv, size_t avail,
		  struct l1sync_basic_port_ds *bds)
{
	const struct l1sync_tlv *ls = (const struct l1sync_tlv *) tlv;

	if (avail < sizeof(*ls)) {
		return -1;
	}
	if (tlv->type != TLV_L1_SYNC) {
		return -1;
	}
	if (tlv->length < L1SYNC_LEN_BASIC ||
	    tlv->length > avail - sizeof(struct TLV)) {
		return -1;
	}

	bds->peerTxCoherentIsRequired =
		(ls->config & L1SYNC_TCR) ? TRUE : FALSE;
	bds->peerRxCoherentIsRequired =
		(ls->config & L1SYNC_RCR) ? TRUE : FALSE;
	bds->peerCongruentIsRequired =
		(ls->config & L1SYNC_CR) ? TRUE : FALSE;
	bds->peerIsTxCoherent = (ls->active & L1SYNC_ITC) ? TRUE : FALSE;
	bds->peerIsRxCoherent = (ls->active & L1SYNC_IRC) ? TRUE : FALSE;
	bds->peerIsCongruent = (ls->active & L1SYNC_IC) ? TRUE : FALSE;

	return 0;
}

const char *l1sync_state_name(Enumeration8 state)
{
	switch (state) {
	case L1S_DISABLED:
		return "DISABLED";
	case L1S_IDLE:
		return "IDLE";
	case L1S_LINK_ALIVE:
		return "LINK_ALIVE";
	case L1S_CONFIG_MATCH:
		return "CONFIG_MATCH";
	case L1S_L1_SYNC_UP:
		return "L1_SYNC_UP";
	}
	return "UNKNOWN";
}
