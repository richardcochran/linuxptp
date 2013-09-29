/**
 * @file uds.c
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "contain.h"
#include "print.h"
#include "transport_private.h"
#include "uds.h"

char uds_path[MAX_IFNAME_SIZE + 1] = "/var/run/ptp4l";

#define UDS_FILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) /*0660*/

struct uds {
	struct transport t;
	struct sockaddr_un sa;
	socklen_t len;
};

static int uds_close(struct transport *t, struct fdarray *fda)
{
	close(fda->fd[FD_GENERAL]);
	return 0;
}

static int uds_open(struct transport *t, char *name, struct fdarray *fda,
		    enum timestamp_type tt)
{
	int fd, err;
	struct sockaddr_un sa;
	struct uds *uds = container_of(t, struct uds, t);

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0) {
		pr_err("uds: failed to create socket: %m");
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_LOCAL;
	strncpy(sa.sun_path, name, sizeof(sa.sun_path) - 1);

	unlink(name);

	err = bind(fd, (struct sockaddr *) &sa, sizeof(sa));
	if (err < 0) {
		pr_err("uds: bind failed: %m");
		close(fd);
		return -1;
	}

	/* For client use, pre load the server path. */
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_LOCAL;
	strncpy(sa.sun_path, uds_path, sizeof(sa.sun_path) - 1);
	uds->sa = sa;
	uds->len = sizeof(sa);

	chmod(name, UDS_FILEMODE);
	fda->fd[FD_EVENT] = -1;
	fda->fd[FD_GENERAL] = fd;
	return 0;
}

static int uds_recv(struct transport *t, int fd, void *buf, int buflen,
		    struct hw_timestamp *hwts)
{
	int cnt;
	struct uds *uds = container_of(t, struct uds, t);
	socklen_t *len = &uds->len;
	uds->len = sizeof(uds->sa);
	cnt = recvfrom(fd, buf, buflen, 0, (struct sockaddr *) &uds->sa, len);
	if (cnt <= 0) {
		pr_err("uds: recvfrom failed: %m");
	}
	return cnt;
}

static int uds_send(struct transport *t, struct fdarray *fda, int event,
		    int peer, void *buf, int buflen, struct hw_timestamp *hwts)
{
	int cnt, fd = fda->fd[FD_GENERAL];
	struct uds *uds = container_of(t, struct uds, t);
	cnt = sendto(fd, buf, buflen, 0, (struct sockaddr *) &uds->sa, uds->len);
	if (cnt <= 0) {
		pr_err("uds: sendto failed: %m");
	}
	return cnt;
}

static void uds_release(struct transport *t)
{
	struct uds *uds = container_of(t, struct uds, t);
	free(uds);
}

struct transport *uds_transport_create(void)
{
	struct uds *uds;
	uds = calloc(1, sizeof(*uds));
	if (!uds)
		return NULL;
	uds->t.close   = uds_close;
	uds->t.open    = uds_open;
	uds->t.recv    = uds_recv;
	uds->t.send    = uds_send;
	uds->t.release = uds_release;
	return &uds->t;
}

