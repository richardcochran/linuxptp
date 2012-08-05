/**
 * @file util.h
 * @brief Various little utility functions that do not fit in elsewhere.
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
#ifndef HAVE_UTIL_H
#define HAVE_UTIL_H

#include "ddt.h"

/**
 * Table of human readable strings, one for each port state.
 */
extern char *ps_str[];

/**
 * Table of human readable strings, one for each port event.
 */
extern char *ev_str[];

/**
 * Convert a clock identity into a human readable string.
 *
 * Note that this function uses a static global variable to store the
 * result and therefore is not reentrant.
 *
 * @param id  Clock idendtity to show.
 * @return    Pointer to a static global buffer holding the result.
 */
char *cid2str(struct ClockIdentity *id);

/**
 * Convert a port identity into a human readable string.
 *
 * Note that this function uses a static global variable to store the
 * result and therefore is not reentrant.
 *
 * @param id  Port idendtity to show.
 * @return    Pointer to a static global buffer holding the result.
 */
char *pid2str(struct PortIdentity *id);

int generate_clock_identity(struct ClockIdentity *ci, char *name);

#endif
