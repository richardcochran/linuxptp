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

#include "fd.h"

enum transport_type {
	TRANS_UDP_IPV4,
	TRANS_UDP_IPV6,
	TRANS_IEEE_802_3,
	TRANS_DEVICENET,
	TRANS_CONTROLNET,
	TRANS_PROFINET,
	TRANS_UDS,
};

enum timestamp_type {
	TS_SOFTWARE,
	TS_HARDWARE,
	TS_LEGACY_HW,
};

struct hw_timestamp {
	enum timestamp_type type;
	struct timespec ts;
};

struct transport;

int transport_close(struct transport *t, struct fdarray *fda);

int transport_open(struct transport *t, char *name,
		   struct fdarray *fda, enum timestamp_type tt);

int transport_recv(struct transport *t, int fd,
		   void *buf, int buflen, struct hw_timestamp *hwts);

int transport_send(struct transport *t, struct fdarray *fda, int event,
		   void *buf, int buflen, struct hw_timestamp *hwts);

int transport_peer(struct transport *t, struct fdarray *fda, int event,
		   void *buf, int buflen, struct hw_timestamp *hwts);

/**
 * Allocate an instance of the specified transport.
 * @param type  Which transport to obtain.
 * @return      Pointer to a transport instance on success, NULL otherwise.
 */
struct transport *transport_create(enum transport_type type);

/**
 * Free an instance of a transport.
 * @param t Pointer obtained by calling transport_create().
 */
void transport_destroy(struct transport *t);

#endif
