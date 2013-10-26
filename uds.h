/**
 * @file uds.h
 * @brief Implements a management interface via UNIX domain sockets.
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
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
#ifndef HAVE_UDS_H
#define HAVE_UDS_H

#include "config.h"
#include "fd.h"
#include "transport.h"

/**
 * Address of the server.
 */
extern char uds_path[MAX_IFNAME_SIZE + 1];

/**
 * Allocate an instance of a UDS transport.
 * @return Pointer to a new transport instance on success, NULL otherwise.
 */
struct transport *uds_transport_create(void);

#endif
