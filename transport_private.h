/**
 * @file transport_private.h
 * @brief Defines a private interface for the abstract transport layer.
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
#ifndef HAVE_TRANSPORT_PRIVATE_H
#define HAVE_TRANSPORT_PRIVATE_H

#include <time.h>

#include "address.h"
#include "fd.h"
#include "transport.h"

struct transport {
	enum transport_type type;
	struct config *cfg;

	int (*close)(struct transport *t, struct fdarray *fda);

	int (*open)(struct transport *t, const char *name, struct fdarray *fda,
		    enum timestamp_type tt);

	int (*recv)(struct transport *t, int fd, void *buf, int buflen,
		    struct address *addr, struct hw_timestamp *hwts);

	int (*send)(struct transport *t, struct fdarray *fda, int event,
		    int peer, void *buf, int buflen, struct address *addr,
		    struct hw_timestamp *hwts);

	void (*release)(struct transport *t);

	int (*physical_addr)(struct transport *t, uint8_t *addr);

	int (*protocol_addr)(struct transport *t, uint8_t *addr);
};

#endif
