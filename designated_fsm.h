/**
 * @file designated_fsm.c
 * @brief Implements designated Finite State Machines.
 * @note Copyright (C) 2018 Intel Corporation
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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA.
 */
#ifndef HAVE_DESIGNATED_FSM_H
#define HAVE_DESIGNATED_FSM_H

#include "fsm.h"

/**
 * Run the state machine for a clock which is designated as master port.
 * @param state  The current state of the port.
 * @param event  The event to be processed.
 * @param mdiff  This param is not used by this function.
 * @return       The new state for the port.
 */
enum port_state designated_master_fsm(enum port_state state,
				      enum fsm_event event,
				      int mdiff);

/**
 * Run the state machine for a clock designated as slave port.
 * @param state  The current state of the port.
 * @param event  The event to be processed.
 * @param mdiff  This param is not used by this function.
 * @return       The new state for the port.
 */
enum port_state designated_slave_fsm(enum port_state state,
				     enum fsm_event event,
				     int mdiff);
#endif
