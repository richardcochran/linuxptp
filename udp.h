/**
 * @file udp.h
 * @brief Implements transport over IPv4 UDP.
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
#ifndef HAVE_UPD_H
#define HAVE_UPD_H

#include "fd.h"
#include "transport.h"

int udp_close(struct fdarray *fda);
int udp_open(char *name, struct fdarray *fda, enum timestamp_type ts_type);
int udp_recv(int fd, void *buf, int buflen, struct hw_timestamp *hwts);
int udp_send(struct fdarray *fda, int event,
	     void *buf, int buflen, struct hw_timestamp *hwts);

/**
 * Obtain the MAC address of a network interface.
 * @param name  The name of the interface
 * @param mac   Buffer to hold the result
 * @param len   Length of 'mac'
 * @return      Zero on success, non-zero otherwise.
 */
int udp_interface_macaddr(char *name, unsigned char *mac, int len);

#endif
