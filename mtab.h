/**
 * @file mtab.h
 * @brief master table implementation
 * @note Copyright (C) 2018 Richard Cochran <richardcochran@gmail.com>
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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA.
 */
#ifndef HAVE_MTAB_H
#define HAVE_MTAB_H

#include <sys/queue.h>
#include <time.h>

#include "address.h"
#include "pdt.h"
#include "transport.h"

struct unicast_master_address {
	STAILQ_ENTRY(unicast_master_address) list;
	struct PortIdentity portIdentity;
	enum transport_type type;
	struct address address;
	unsigned int granted;
	unsigned int sydymsk;
	time_t renewal_tmo;
};

struct unicast_master_table {
	STAILQ_HEAD(addrs_head, unicast_master_address) addrs;
	STAILQ_ENTRY(unicast_master_table) list;
	Integer8 logQueryInterval;
	int table_index;
	int count;
	int port;
	/* for use with P2P delay mechanism: */
	struct unicast_master_address peer_addr;
	char *peer_name;
};

#endif
