/**
 * @file l1_state.c
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
#include <string.h>

#include "l1_state.h"
#include "provider.h"

static struct provider l1_state = {
	.name = "L1 state provider",
	.fallback = "reporting no coherency",
	.magic = L1_STATE_MAGIC,
	.version = L1_STATE_VERSION,
	.fd = -1,
};

int l1_state_init(struct config *cfg)
{
	return provider_open(&l1_state, cfg, "l1_state_provider",
			     "l1_state_timeout");
}

void l1_state_cleanup(void)
{
	provider_close(&l1_state);
}

static void l1_state_request(struct l1_state_request *req,
			     unsigned int ifindex, enum l1_state_command cmd)
{
	memset(req, 0, sizeof(*req));
	req->magic = L1_STATE_MAGIC;
	req->version = L1_STATE_VERSION;
	req->command = cmd;
	req->ifindex = ifindex;
	req->xid = ++l1_state.xid;
}

void l1_state_command(unsigned int ifindex, enum l1_state_command cmd)
{
	struct l1_state_request req;

	if (l1_state.fd < 0) {
		return;
	}
	l1_state_request(&req, ifindex, cmd);
	if (provider_send(&l1_state, &req, sizeof(req))) {
		provider_fail(&l1_state, "request failed");
	}
}

void l1_state_query(unsigned int ifindex, struct l1_state *st)
{
	struct l1_state_request req;
	struct l1_state_reply rep;

	memset(st, 0, sizeof(*st));

	if (l1_state.fd < 0) {
		provider_fail(&l1_state, "not configured");
		return;
	}
	l1_state_request(&req, ifindex, L1_CMD_QUERY);
	if (provider_exchange(&l1_state, &req, sizeof(req), req.xid,
			      &rep, sizeof(rep))) {
		return;
	}
	if (!(rep.flags & L1_STATE_VALID)) {
		provider_fail(&l1_state,
			      "cannot determine the state of the interface");
		return;
	}
	st->isTxCoherent = (rep.flags & L1_STATE_TX_COHERENT) ? TRUE : FALSE;
	st->isRxCoherent = (rep.flags & L1_STATE_RX_COHERENT) ? TRUE : FALSE;
	st->isCongruent = (rep.flags & L1_STATE_CONGRUENT) ? TRUE : FALSE;
	l1_state.failures = 0;
}
