/**
 * @file port_l1sync.c
 * @brief Drives the L1Sync state machine of a PTP port.
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
#include <string.h>

#include "contain.h"
#include "l1sync_fsm.h"
#include "port.h"
#include "port_private.h"
#include "print.h"
#include "tlv.h"
#include "transport.h"

#define L1SYNC_LOG_INTERVAL 256

/*
 * The order in which the conditions of Table L.5 are offered: the ANY
 * STATE arcs first, then the mismatches, a configuration mismatch going
 * further back than a state mismatch.
 */
static const enum l1sync_event l1sync_precedence[] = {
	L1S_EV_RESET,
	L1S_EV_LINK_DOWN,
	L1S_EV_ENABLED,
	L1S_EV_CONFIG_MISMATCH,
	L1S_EV_STATE_MISMATCH,
	L1S_EV_LINK_OK,
	L1S_EV_CONFIG_OK,
	L1S_EV_STATE_OK,
};

static int l1sync_capable(struct port *p)
{
	/* A global L1SyncEnabled also reaches the UDS port. */
	return p->l1sync.L1SyncEnabled &&
	       transport_type(p->trp) != TRANS_UDS;
}

static int l1sync_set_tx_tmo(struct port *p)
{
	/* L.6.2: within 30% of the interval, per 9.5.8. */
	return set_tmo_random(p->fda.fd[FD_L1SYNC_TX_TIMER], 0.7, 0.6,
			      p->l1sync.logL1SyncInterval);
}

static int l1sync_set_rx_tmo(struct port *p)
{
	return set_tmo_log(p->fda.fd[FD_L1SYNC_RX_TIMER],
			   p->l1sync.L1SyncReceiptTimeout,
			   p->l1sync.logL1SyncInterval);
}

static void l1sync_derive(struct port *p)
{
	struct l1sync_basic_port_ds *bds = &p->l1sync;

	/* L.5.1: the initialization values hold throughout DISABLED. */
	if (bds->L1SyncState == L1S_DISABLED) {
		return;
	}

	bds->isTxCoherent = FALSE;
	bds->isRxCoherent = FALSE;

	/* L.5.3.4 NOTE 2 */
	switch (p->state) {
	case PS_MASTER:
	case PS_GRAND_MASTER:
		bds->isCongruent = bds->isTxCoherent;
		break;
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		bds->isCongruent = bds->isRxCoherent;
		break;
	default:
		bds->isCongruent = FALSE;
		break;
	}
}

static int l1sync_tx(struct port *p)
{
	struct PortIdentity tpid;
	struct ptp_message *msg;
	struct tlv_extra *extra;
	struct l1sync_tlv *ls;
	int err;

	if (p->l1sync.L1SyncState == L1S_DISABLED || !port_is_enabled(p)) {
		return 0;
	}

	memset(&tpid, 0xff, sizeof(tpid));
	msg = port_signaling_construct(p, &tpid);
	if (!msg) {
		return -1;
	}
	extra = msg_tlv_append(msg, sizeof(*ls));
	if (!extra) {
		err = -1;
		goto out;
	}
	ls = (struct l1sync_tlv *) extra->tlv;
	l1sync_pack(ls, &p->l1sync);

	/* L.6.1: the nonforwardable address, as used for peer delay. */
	err = peer_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: send L1Sync signaling failed", p->log_name);
	}
out:
	msg_put(msg);
	return err;
}

static void l1sync_transition(struct port *p, enum l1sync_state next)
{
	struct l1sync_basic_port_ds *bds = &p->l1sync;

	pr_notice("%s: L1Sync %s to %s", p->log_name,
		  l1sync_state_name(bds->L1SyncState),
		  l1sync_state_name(next));
	bds->L1SyncState = next;

	switch (next) {
	case L1S_DISABLED:
		l1sync_reset_dynamic(bds);	/* L.5.1 */
		port_clr_tmo(p->fda.fd[FD_L1SYNC_TX_TIMER]);
		port_clr_tmo(p->fda.fd[FD_L1SYNC_RX_TIMER]);
		break;
	case L1S_IDLE:
		l1sync_reset_peer(bds);		/* L.5.1 */
		l1sync_derive(p);
		port_clr_tmo(p->fda.fd[FD_L1SYNC_RX_TIMER]);
		l1sync_set_tx_tmo(p);
		l1sync_tx(p);
		break;
	case L1S_LINK_ALIVE:
	case L1S_CONFIG_MATCH:
	case L1S_L1_SYNC_UP:
		l1sync_derive(p);
		break;
	}
}

static int l1sync_holds(struct port *p, enum l1sync_event ev)
{
	const struct l1sync_basic_port_ds *bds = &p->l1sync;

	/* Table L.5, plus L1_SYNC_RESET from L.7.4.3. */
	switch (ev) {
	case L1S_EV_RESET:
		return !l1sync_capable(p) || p->l1sync_reset;
	case L1S_EV_ENABLED:
		return l1sync_capable(p) && !p->l1sync_reset;
	case L1S_EV_LINK_DOWN:
		return !bds->L1SyncLinkAlive;
	case L1S_EV_LINK_OK:
		return bds->L1SyncLinkAlive != FALSE;
	case L1S_EV_CONFIG_MISMATCH:
		return !l1sync_config_ok(bds);
	case L1S_EV_CONFIG_OK:
		return l1sync_config_ok(bds);
	case L1S_EV_STATE_MISMATCH:
		return !l1sync_state_ok(bds);
	case L1S_EV_STATE_OK:
		return l1sync_state_ok(bds);
	}
	return 0;
}

void port_l1sync_update(struct port *p)
{
	enum l1sync_state next = p->l1sync.L1SyncState;
	unsigned int i, step;

	if (!l1sync_capable(p) && p->l1sync.L1SyncState == L1S_DISABLED) {
		return;
	}
	l1sync_derive(p);

	/* One change may walk the machine through several states. */
	for (step = 0; step < ARRAY_SIZE(l1sync_precedence); step++) {
		for (i = 0; i < ARRAY_SIZE(l1sync_precedence); i++) {
			if (!l1sync_holds(p, l1sync_precedence[i])) {
				continue;
			}
			next = l1sync_fsm(p->l1sync.L1SyncState,
					  l1sync_precedence[i]);
			if (next != p->l1sync.L1SyncState) {
				break;
			}
		}
		if (i == ARRAY_SIZE(l1sync_precedence)) {
			return;
		}
		l1sync_transition(p, next);
	}
	pr_err("%s: L1Sync state machine did not settle", p->log_name);
}

void port_l1sync_initialize(struct port *p)
{
	p->l1sync_reset = 0;
	port_l1sync_update(p);
}

void port_l1sync_disable(struct port *p)
{
	if (p->l1sync.L1SyncState != L1S_DISABLED) {
		l1sync_transition(p, L1S_DISABLED);
	}
}

void port_l1sync_link_status(struct port *p, int linkup)
{
	/* I.5.3 a): L1SYNC_RESET is a disconnection of the interface. */
	p->l1sync_reset = linkup ? 0 : 1;
	port_l1sync_update(p);
}

void port_l1sync_recv(struct port *p, struct ptp_message *m)
{
	static unsigned int malformed, uncorrected;
	struct l1sync_basic_port_ds *bds = &p->l1sync;
	struct tlv_extra *extra;
	int applied = 0;
	size_t avail;

	if (bds->L1SyncState == L1S_DISABLED) {
		return;
	}
	/* L.6.3: the TLV is evaluated on any received message. */
	TAILQ_FOREACH(extra, &m->tlv_list, list) {
		if (extra->tlv->type != TLV_L1_SYNC) {
			continue;
		}
		avail = sizeof(struct TLV) + extra->tlv->length;
		if (l1sync_unpack(extra->tlv, avail, bds)) {
			if (!(malformed++ % L1SYNC_LOG_INTERVAL)) {
				pr_warning("%s: malformed L1_SYNC TLV",
					   p->log_name);
			}
			continue;
		}
		applied = 1;
	}
	if (!applied) {
		return;
	}
	if (msg_type(m) == SIGNALING && m->header.correction &&
	    !(uncorrected++ % L1SYNC_LOG_INTERVAL)) {
		/* Table 38 */
		pr_warning("%s: peer sends signaling with a correction",
			   p->log_name);
	}

	bds->L1SyncLinkAlive = TRUE;
	l1sync_set_rx_tmo(p);
	port_l1sync_update(p);
}

enum fsm_event port_l1sync_tx_timeout(struct port *p)
{
	l1sync_set_tx_tmo(p);
	return l1sync_tx(p) ? EV_FAULT_DETECTED : EV_NONE;
}

enum fsm_event port_l1sync_rx_timeout(struct port *p)
{
	p->l1sync.L1SyncLinkAlive = FALSE;
	port_l1sync_update(p);
	return EV_NONE;
}
