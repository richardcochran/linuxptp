/**
 * @file provider.h
 * @brief Client of a helper process on a UNIX domain datagram socket.
 * @note Copyright (C) 2026 Liquid Instruments Pty Ltd
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
#ifndef HAVE_PROVIDER_H
#define HAVE_PROVIDER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/un.h>

#include "config.h"
#include "ddt.h"

struct provider {
	const char *name;
	const char *fallback;		/**< what a failure means, for the log */
	uint32_t magic;
	uint8_t version;
	int fd;
	int timeout;			/**< milliseconds */
	uint32_t xid;
	unsigned int failures;
	struct sockaddr_un sa;
};

/** Every reply starts with this. */
struct provider_reply {
	uint32_t	magic;
	uint8_t		version;
	uint8_t		data;
	uint16_t	reserved;
	uint32_t	xid;
} PACKED;

/**
 * Open the socket if the option @a path_opt names a provider.
 * @return  Zero on success or when none is configured, -1 on error.
 */
int provider_open(struct provider *pv, struct config *cfg,
		  const char *path_opt, const char *timeout_opt);

void provider_close(struct provider *pv);

/** Log a failure, rate limited. */
void provider_fail(struct provider *pv, const char *reason);

/** Send a request without waiting for a reply. */
int provider_send(struct provider *pv, const void *req, size_t len);

/**
 * Send a request and wait for the reply carrying @a xid, discarding
 * stale replies.  Failures are logged.
 * @return  Zero if @a rep holds the reply, -1 otherwise.
 */
int provider_exchange(struct provider *pv, const void *req, size_t reqlen,
		      uint32_t xid, void *rep, size_t replen);

#endif
