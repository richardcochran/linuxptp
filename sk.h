/**
 * @file sk.h
 * @brief Implements protocol independent socket methods.
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
#ifndef HAVE_SK_H
#define HAVE_SK_H

#include "transport.h"

/**
 * Obtain the numerical index from a network interface by name.
 * @param fd      An open socket.
 * @param device  The name of the network interface of interest.
 * @return        The result from the SIOCGIFINDEX ioctl.
 */
int sk_interface_index(int fd, char *device);

/**
 * Obtain the PHC device index of a network interface.
 * @param name	    The name of the interface
 * @return index    The non-negative phc index associated with this iface.
 *                  On error a negative integer is returned.
 */
int sk_interface_phc(char *name, int *index);

/**
 * Obtain the MAC address of a network interface.
 * @param name  The name of the interface
 * @param mac   Buffer to hold the result
 * @param len   Length of 'mac'
 * @return      Zero on success, non-zero otherwise.
 */
int sk_interface_macaddr(char *name, unsigned char *mac, int len);

/**
 * Read a message from a socket.
 * @param fd      An open socket.
 * @param buf     Buffer to receive the message.
 * @param buflen  Size of 'buf' in bytes.
 * @param hwts    Pointer to a buffer to receive the message's time stamp.
 * @param flags   Flags to pass to RECV(2).
 * @return
 */
int sk_receive(int fd, void *buf, int buflen,
	       struct hw_timestamp *hwts, int flags);

/**
 * Enable time stamping on a given network interface.
 * @param fd          An open socket.
 * @param device      The name of the network interface to configure.
 * @param type        The requested flavor of time stamping.
 * @param transport   The type of transport used.
 * @return            Zero on success, non-zero otherwise.
 */
int sk_timestamping_init(int fd, char *device, enum timestamp_type type,
			 enum transport_type transport);

/**
 * Limits the number of RECVMSG(2) calls when attempting to obtain a
 * transmit time stamp on an event message.
 */
extern int sk_tx_retries;

#endif
