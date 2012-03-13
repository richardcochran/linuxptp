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

/**
 * Obtain the MAC address of a network interface.
 * @param name  The name of the interface
 * @param mac   Buffer to hold the result
 * @param len   Length of 'mac'
 * @return      Zero on success, non-zero otherwise.
 */
int udp_interface_macaddr(char *name, unsigned char *mac, int len);

/**
 * Allocate an instance of a UDP/IPv4 transport.
 * @return Pointer to a new transport instance on success, NULL otherwise.
 */
struct transport *udp_transport_create(void);

/**
 * Free an instance of a UDP/IPv4 transport.
 * @param t Pointer obtained by calling udp_transport_create().
 */
void udp_transport_destroy(struct transport *t);

#endif
