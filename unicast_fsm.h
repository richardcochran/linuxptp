/**
 * @file unicast_fsm.h
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
#ifndef HAVE_UNICAST_FSM_H
#define HAVE_UNICAST_FSM_H

enum unicast_state {
	UC_WAIT,
	UC_HAVE_ANN,
	UC_NEED_SYDY,
	UC_HAVE_SYDY,
};

enum unicast_event {
	UC_EV_GRANT_ANN,
	UC_EV_SELECTED,
	UC_EV_GRANT_SYDY,
	UC_EV_UNSELECTED,
	UC_EV_CANCEL,
};

enum unicast_state unicast_fsm(enum unicast_state state, enum unicast_event ev);

#endif
