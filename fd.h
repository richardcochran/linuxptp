/**
 * @file fd.h
 * @brief Defines a array of file descriptors, useful for polling.
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
#ifndef HAVE_FD_H
#define HAVE_FD_H

#define N_TIMER_FDS 8

/*
 * The order matters here.  The DELAY timer must appear before the
 * ANNOUNCE and SYNC_RX timers in order to correctly handle the case
 * when the DELAY timer and one of the other two expire during the
 * same call to poll().
 */
enum {
	FD_EVENT,
	FD_GENERAL,
	FD_DELAY_TIMER,
	FD_ANNOUNCE_TIMER,
	FD_SYNC_RX_TIMER,
	FD_QUALIFICATION_TIMER,
	FD_MANNO_TIMER,
	FD_SYNC_TX_TIMER,
	FD_UNICAST_REQ_TIMER,
	FD_UNICAST_SRV_TIMER,
	FD_RTNL,
	N_POLLFD,
};

#define FD_FIRST_TIMER FD_DELAY_TIMER

struct fdarray {
	int fd[N_POLLFD];
};

#endif
