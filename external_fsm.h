/**
 * @file external_fsm.h
 * @brief External configuration of a PTP port state, clause 17.6.
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
#ifndef HAVE_EXTERNAL_FSM_H
#define HAVE_EXTERNAL_FSM_H

#include "fsm.h"

/**
 * Run the port state machine for a port whose state is configured
 * externally, per IEEE 1588-2019 17.6.
 * @param state    The current state of the port.
 * @param event    The event to be processed.
 * @param desired  externalPortConfigurationPortDS.desiredState.
 * @return         The new state for the port.
 */
enum port_state external_fsm(enum port_state state, enum fsm_event event,
			     enum port_state desired);

#endif
