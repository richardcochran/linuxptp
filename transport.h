/**
 * @file transport.h
 * @brief Defines an abstract transport layer.
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
#ifndef HAVE_TRANSPORT_H
#define HAVE_TRANSPORT_H

#include <time.h>
#include <inttypes.h>

#include "fd.h"
#include "msg.h"

struct config;

/* Values from networkProtocol enumeration 7.4.1 Table 3 */
enum transport_type {
	/* 0 is Reserved in spec. Use it for UDS */
	TRANS_UDS = 0,
	TRANS_UDP_IPV4 = 1,
	TRANS_UDP_IPV6,
	TRANS_IEEE_802_3,
	TRANS_DEVICENET,
	TRANS_CONTROLNET,
	TRANS_PROFINET,
};

/**
 * Values for the 'event' parameter in transport_send() and
 * transport_peer().
 */
enum transport_event {
	TRANS_GENERAL,
	TRANS_EVENT,
	TRANS_ONESTEP,
};

struct transport;

int transport_close(struct transport *t, struct fdarray *fda);

int transport_open(struct transport *t, const char *name,
		   struct fdarray *fda, enum timestamp_type tt);

int transport_recv(struct transport *t, int fd, struct ptp_message *msg);

/**
 * Sends the PTP message using the given transport. The message is sent to
 * the default (usually multicast) address, any address field in the
 * ptp_message itself is ignored.
 * @param t	The transport.
 * @param fda	The array of descriptors filled in by transport_open.
 * @param event	1 for event message, 0 for general message.
 * @param msg	The message to send.
 * @return	Number of bytes send, or negative value in case of an error.
 */
int transport_send(struct transport *t, struct fdarray *fda, int event,
		   struct ptp_message *msg);

/**
 * Sends the PTP message using the given transport. The message is sent to
 * the address used for p2p delay measurements (usually a multicast
 * address), any address field in the ptp_message itself is ignored.
 * @param t	The transport.
 * @param fda	The array of descriptors filled in by transport_open.
 * @param event	1 for event message, 0 for general message.
 * @param msg	The message to send.
 * @return	Number of bytes send, or negative value in case of an error.
 */
int transport_peer(struct transport *t, struct fdarray *fda, int event,
		   struct ptp_message *msg);

/**
 * Sends the PTP message using the given transport. The address has to be
 * provided in the address field of the message.
 * @param t	The transport.
 * @param fda	The array of descriptors filled in by transport_open.
 * @param event	1 for event message, 0 for general message.
 * @param msg	The message to send. The address of the destination has to
 *		be set in the address field.
 * @return	Number of bytes send, or negative value in case of an error.
 */
int transport_sendto(struct transport *t, struct fdarray *fda, int event,
		     struct ptp_message *msg);

/**
 * Returns the transport's type.
 */
enum transport_type transport_type(struct transport *t);

#define TRANSPORT_ADDR_LEN 16

/**
 * Gets the transport's physical address.
 * @param t    The transport.
 * @param addr The address will be written to this buffer.
 * @return     The number of bytes written to the buffer. Will be 0-16
 *             bytes
 */
int transport_physical_addr(struct transport *t, uint8_t *addr);

/**
 * Gets the transport's protocol address.
 * @param t    The transport.
 * @param addr The address will be written to this buffer.
 * @return     The number of bytes written to the buffer. Will be 0-16
 *             bytes
 */
int transport_protocol_addr(struct transport *t, uint8_t *addr);

/**
 * Allocate an instance of the specified transport.
 * @param config Pointer to the configuration database.
 * @param type  Which transport to obtain.
 * @return      Pointer to a transport instance on success, NULL otherwise.
 */
struct transport *transport_create(struct config *cfg,
				   enum transport_type type);

/**
 * Free an instance of a transport.
 * @param t Pointer obtained by calling transport_create().
 */
void transport_destroy(struct transport *t);

#endif
