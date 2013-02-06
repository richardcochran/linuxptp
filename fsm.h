/**
 * @file fsm.h
 * @brief The finite state machine for ports on boundary and ordinary clocks.
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
#ifndef HAVE_FSM_H
#define HAVE_FSM_H

/** Defines the state of a port. */
enum port_state {
	PS_INITIALIZING = 1,
	PS_FAULTY,
	PS_DISABLED,
	PS_LISTENING,
	PS_PRE_MASTER,
	PS_MASTER,
	PS_PASSIVE,
	PS_UNCALIBRATED,
	PS_SLAVE,
	PS_GRAND_MASTER, /*non-standard extension*/
};

/** Defines the events for the port state machine. */
enum fsm_event {
	EV_NONE,
	EV_POWERUP,
	EV_INITIALIZE,
	EV_DESIGNATED_ENABLED,
	EV_DESIGNATED_DISABLED,
	EV_FAULT_CLEARED,
	EV_FAULT_DETECTED,
	EV_STATE_DECISION_EVENT,
	EV_QUALIFICATION_TIMEOUT_EXPIRES,
	EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES,
	EV_SYNCHRONIZATION_FAULT,
	EV_MASTER_CLOCK_SELECTED,
	EV_RS_MASTER,
	EV_RS_GRAND_MASTER,
	EV_RS_SLAVE,
	EV_RS_PASSIVE,
};

/**
 * Run the state machine for a BC or OC port.
 * @param state  The current state of the port.
 * @param event  The event to be processed.
 * @param mdiff  Whether a new master has been selected.
 * @return       The new state for the port.
 */
enum port_state ptp_fsm(enum port_state state, enum fsm_event event, int mdiff);

/**
 * Run the state machine for a slave only clock.
 * @param state  The current state of the port.
 * @param event  The event to be processed.
 * @param mdiff  Whether a new master has been selected.
 * @return       The new state for the port.
 */
enum port_state ptp_slave_fsm(enum port_state state, enum fsm_event event,
			      int mdiff);

#endif
