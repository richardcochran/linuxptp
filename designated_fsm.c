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
#include "fsm.h"
#include "designated_fsm.h"

enum port_state designated_master_fsm(enum port_state state,
				      enum fsm_event event,
				      int mdiff)
{
	enum port_state next = state;

	if (EV_INITIALIZE == event || EV_POWERUP == event)
		return PS_INITIALIZING;

	switch (state) {
	case PS_INITIALIZING:
		switch (event) {
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_INIT_COMPLETE:
			next = PS_MASTER;
			break;
		default:
			break;
		}
		break;

	case PS_FAULTY:
		if (event == EV_FAULT_CLEARED) {
			next = PS_INITIALIZING;
		}
		break;

	case PS_MASTER:
		if (event == EV_FAULT_DETECTED) {
			next = PS_FAULTY;
		}
		break;

	default:
		break;
	}
	return next;
}

enum port_state designated_slave_fsm(enum port_state state,
				     enum fsm_event event,
				     int mdiff)
{
	enum port_state next = state;

	if (EV_INITIALIZE == event || EV_POWERUP == event)
		return PS_INITIALIZING;

	switch (state) {
	case PS_INITIALIZING:
		switch (event) {
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		case EV_INIT_COMPLETE:
			next =  PS_SLAVE;
			break;
		default:
			break;
		}
		break;

	case PS_FAULTY:
		if (event == EV_FAULT_CLEARED) {
			next = PS_INITIALIZING;
		}
		break;

	case PS_SLAVE:
		switch (event) {
		case EV_FAULT_DETECTED:
			next = PS_FAULTY;
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}
	return next;
}
