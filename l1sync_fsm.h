/**
 * @file l1sync_fsm.h
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
#ifndef HAVE_L1SYNC_FSM_H
#define HAVE_L1SYNC_FSM_H

#include "l1sync.h"

/**
 * Events of Figure L.4.  Each local variable of Table L.5 appears in both
 * polarities, and L1_SYNC_RESET shares the arc of !L1_SYNC_ENABLED.
 */
enum l1sync_event {
	/** !L1_SYNC_ENABLED, or the L1_SYNC_RESET event of L.7.4.3 */
	L1S_EV_RESET,
	L1S_EV_ENABLED,			/**< L1_SYNC_ENABLED */
	L1S_EV_LINK_DOWN,		/**< !LINK_OK */
	L1S_EV_LINK_OK,			/**< LINK_OK */
	L1S_EV_CONFIG_MISMATCH,		/**< !CONFIG_OK */
	L1S_EV_CONFIG_OK,		/**< CONFIG_OK */
	L1S_EV_STATE_MISMATCH,		/**< !STATE_OK */
	L1S_EV_STATE_OK,		/**< STATE_OK */
};

/**
 * Run the state machine of Figure L.4.
 * @param state  The current state.
 * @param ev     The event that has occurred.
 * @return       The next state, which may be the current one.
 */
enum l1sync_state l1sync_fsm(enum l1sync_state state, enum l1sync_event ev);

#endif
