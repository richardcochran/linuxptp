/**
 * @file sock.h
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SOCK_H
#define HAVE_SOCK_H

/**
 * Opens a socket connected to a given remote address.
 * @param server	Host name or IP address of the server.
 * @param port		Port on the server with which to connect.
 * @return		An open file descriptor on success, -1 otherwise.
 */
int sock_open(const char *server, const char *port);

#endif
