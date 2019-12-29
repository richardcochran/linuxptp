/**
 * @file sock.c
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <netdb.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>

#include "print.h"
#include "sock.h"

typedef void *so_t;

int sock_open(const char *server, const char *port)
{
	int i, err, family[2] = { AF_INET, AF_INET6 }, fd;
	struct addrinfo	hints, *result = NULL;
	socklen_t addrlen;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_socktype = SOCK_STREAM;

	for (i = 0; i < 2; i++) {
		hints.ai_family = family[i];
		err = getaddrinfo(server, port, &hints, &result);
		if (err) {
			pr_debug("%s: getaddrinfo failed family %d: %s",
				 __func__, hints.ai_family, gai_strerror(err));
			result = NULL;
		} else {
			break;
		}
	}
	if (!result) {
		return -1;
	}

	addrlen = (socklen_t) result->ai_addrlen;
	pr_debug("%s: connecting to server %s canonical %s",
		 __func__, server, result->ai_canonname);

	fd = socket(result->ai_family, SOCK_STREAM, result->ai_protocol);
	if (fd < 0) {
		pr_err("%s: socket failed: %m", __func__);
		goto failed;
	}
	if (connect(fd, result->ai_addr, addrlen) < 0) {
		pr_err("%s: connect failed: %m", __func__);
		close(fd);
		fd = -1;
	}
failed:
	freeaddrinfo(result);
	return fd;
}
