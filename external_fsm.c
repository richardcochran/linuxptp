/**
 * @file external_fsm.c
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
#include "external_fsm.h"

enum port_state external_fsm(enum port_state state, enum fsm_event event,
			     enum port_state desired)
{
	enum port_state next = state;

	if (EV_INITIALIZE == event || EV_POWERUP == event) {
		return PS_INITIALIZING;
	}
	/* 17.6.5.2 permits a fault to override the desired state. */
	if (EV_FAULT_DETECTED == event) {
		return PS_FAULTY;
	}

	switch (state) {
	case PS_INITIALIZING:
		if (EV_INIT_COMPLETE == event) {
			next = desired;
		}
		break;
	case PS_FAULTY:
		if (EV_FAULT_CLEARED == event) {
			next = PS_INITIALIZING;
		}
		break;
	default:
		/* 17.6.5.3: nothing else moves the port. */
		break;
	}
	return next;
}
