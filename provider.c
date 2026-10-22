/**
 * @file provider.c
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
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "print.h"
#include "provider.h"

#define PROVIDER_LOG_INTERVAL 256
#define PROVIDER_MAX_STALE 8

int provider_open(struct provider *pv, struct config *cfg,
		  const char *path_opt, const char *timeout_opt)
{
	struct sockaddr_un sa;
	const char *path;
	int fd;

	path = config_get_string(cfg, NULL, path_opt);
	if (!path || !path[0]) {
		return 0;
	}
	if (strlen(path) >= sizeof(sa.sun_path)) {
		pr_err("%s path is too long", path_opt);
		return -1;
	}

	memset(&pv->sa, 0, sizeof(pv->sa));
	pv->sa.sun_family = AF_UNIX;
	strncpy(pv->sa.sun_path, path, sizeof(pv->sa.sun_path) - 1);
	pv->timeout = config_get_int(cfg, NULL, timeout_opt);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		pr_err("%s socket failed: %m", path_opt);
		return -1;
	}
	/* Autobind, so the provider has an address to reply to. */
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa_family_t))) {
		pr_err("%s bind failed: %m", path_opt);
		close(fd);
		return -1;
	}
	pv->fd = fd;
	pr_info("%s at %s, timeout %d ms", pv->name, path, pv->timeout);
	return 0;
}

void provider_close(struct provider *pv)
{
	if (pv->fd >= 0) {
		close(pv->fd);
		pv->fd = -1;
	}
}

void provider_fail(struct provider *pv, const char *reason)
{
	if (pv->failures++ % PROVIDER_LOG_INTERVAL) {
		return;
	}
	pr_warning("%s: %s, %s", pv->name, reason, pv->fallback);
}

int provider_send(struct provider *pv, const void *req, size_t len)
{
	ssize_t cnt;

	cnt = sendto(pv->fd, req, len, 0,
		     (struct sockaddr *) &pv->sa, sizeof(pv->sa));
	return cnt == (ssize_t) len ? 0 : -1;
}

static int provider_remaining(const struct timespec *start, int budget)
{
	struct timespec now;
	int64_t elapsed;

	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		return 0;
	}
	elapsed = (now.tv_sec - start->tv_sec) * 1000 +
		  (now.tv_nsec - start->tv_nsec) / 1000000;
	if (elapsed >= budget) {
		return 0;
	}
	return budget - (int) elapsed;
}

int provider_exchange(struct provider *pv, const void *req, size_t reqlen,
		      uint32_t xid, void *rep, size_t replen)
{
	struct provider_reply hdr;
	struct timespec start;
	struct pollfd pfd;
	ssize_t cnt;
	int stale;

	if (clock_gettime(CLOCK_MONOTONIC, &start)) {
		provider_fail(pv, "clock_gettime failed");
		return -1;
	}
	if (provider_send(pv, req, reqlen)) {
		provider_fail(pv, "request failed");
		return -1;
	}
	/*
	 * A reply to an earlier request that timed out may be queued ahead
	 * of ours.  Drain it within the same budget, or every later
	 * exchange would read the previous answer.
	 */
	for (stale = 0; stale <= PROVIDER_MAX_STALE; stale++) {
		pfd.fd = pv->fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		cnt = poll(&pfd, 1, provider_remaining(&start, pv->timeout));
		if (cnt < 0) {
			if (errno != EINTR) {
				provider_fail(pv, "poll failed");
			}
			return -1;
		}
		if (!cnt) {
			provider_fail(pv, "timed out");
			return -1;
		}
		cnt = recv(pv->fd, rep, replen, MSG_DONTWAIT);
		if (cnt != (ssize_t) replen) {
			provider_fail(pv, "short reply");
			return -1;
		}
		memcpy(&hdr, rep, sizeof(hdr));
		if (hdr.magic != pv->magic || hdr.version != pv->version) {
			provider_fail(pv, "bad reply");
			return -1;
		}
		if (hdr.xid == xid) {
			return 0;
		}
	}
	provider_fail(pv, "stale replies");
	return -1;
}
