/**
 * @file l1sync_fsm.c
 * @brief L1Sync port state machine
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
#include "l1sync_fsm.h"

enum l1sync_state l1sync_fsm(enum l1sync_state state, enum l1sync_event ev)
{
	enum l1sync_state next = state;

	/* The two ANY STATE arcs of Figure L.4, the second only once running. */
	if (ev == L1S_EV_RESET) {
		return L1S_DISABLED;
	}
	if (ev == L1S_EV_LINK_DOWN) {
		return state == L1S_DISABLED ? L1S_DISABLED : L1S_IDLE;
	}

	switch (state) {
	case L1S_DISABLED:
		if (ev == L1S_EV_ENABLED) {
			next = L1S_IDLE;
		}
		break;
	case L1S_IDLE:
		if (ev == L1S_EV_LINK_OK) {
			next = L1S_LINK_ALIVE;
		}
		break;
	case L1S_LINK_ALIVE:
		if (ev == L1S_EV_CONFIG_OK) {
			next = L1S_CONFIG_MATCH;
		}
		break;
	case L1S_CONFIG_MATCH:
		switch (ev) {
		case L1S_EV_CONFIG_MISMATCH:
			next = L1S_LINK_ALIVE;
			break;
		case L1S_EV_STATE_OK:
			next = L1S_L1_SYNC_UP;
			break;
		default:
			break;
		}
		break;
	case L1S_L1_SYNC_UP:
		switch (ev) {
		case L1S_EV_CONFIG_MISMATCH:
			next = L1S_LINK_ALIVE;
			break;
		case L1S_EV_STATE_MISMATCH:
			next = L1S_CONFIG_MATCH;
			break;
		default:
			break;
		}
		break;
	}
	return next;
}
