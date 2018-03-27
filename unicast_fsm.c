/**
 * @file unicast_fsm.c
 * @brief Unicast client state machine
 * @note Copyright (C) 2018 Richard Cochran <richardcochran@gmail.com>
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
#include "unicast_fsm.h"

enum unicast_state unicast_fsm(enum unicast_state state, enum unicast_event ev)
{
	enum unicast_state next = state;

	switch (state) {
	case UC_WAIT:
		switch (ev) {
		case UC_EV_GRANT_ANN:
			next = UC_HAVE_ANN;
			break;
		case UC_EV_SELECTED:
		case UC_EV_GRANT_SYDY:
		case UC_EV_UNSELECTED:
		case UC_EV_CANCEL:
			break;
		}
		break;
	case UC_HAVE_ANN:
		switch (ev) {
		case UC_EV_GRANT_ANN:
			break;
		case UC_EV_SELECTED:
			next = UC_NEED_SYDY;
			break;
		case UC_EV_GRANT_SYDY:
		case UC_EV_UNSELECTED:
			break;
		case UC_EV_CANCEL:
			next = UC_WAIT;
			break;
		}
		break;
	case UC_NEED_SYDY:
		switch (ev) {
		case UC_EV_GRANT_ANN:
		case UC_EV_SELECTED:
			break;
		case UC_EV_GRANT_SYDY:
			next = UC_HAVE_SYDY;
			break;
		case UC_EV_UNSELECTED:
			next = UC_HAVE_ANN;
			break;
		case UC_EV_CANCEL:
			next = UC_WAIT;
			break;
		}
		break;
	case UC_HAVE_SYDY:
		switch (ev) {
		case UC_EV_GRANT_ANN:
		case UC_EV_SELECTED:
		case UC_EV_GRANT_SYDY:
			break;
		case UC_EV_UNSELECTED:
			next = UC_HAVE_ANN;
			break;
		case UC_EV_CANCEL:
			next = UC_WAIT;
			break;
		}
		break;
	}
	return next;
}
