/**
 * @file interface.h
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_INTERFACE_H
#define HAVE_INTERFACE_H

#include <sys/queue.h>
#include "sk.h"

#define MAX_IFNAME_SIZE 108 /* = UNIX_PATH_MAX */

#if (IF_NAMESIZE > MAX_IFNAME_SIZE)
#error if_namesize larger than expected.
#endif

/** Defines a network interface, with PTP options. */
struct interface {
	STAILQ_ENTRY(interface) list;
	char name[MAX_IFNAME_SIZE + 1];
	char ts_label[MAX_IFNAME_SIZE + 1];
	struct sk_ts_info ts_info;
};

/**
 * Obtains the name of a network interface.
 * @param iface  The interface of interest.
 * @return       The device name of the network interface.
 */
const char *interface_name(struct interface *iface);

#endif

