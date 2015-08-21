/**
 * @file ether.h
 * @brief Provides definitions useful when working with Ethernet packets.
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
#ifndef HAVE_ETHER_H
#define HAVE_ETHER_H

#include <stdint.h>

#define MAC_LEN 6

typedef uint8_t eth_addr[MAC_LEN];

struct eth_hdr {
	eth_addr dst;
	eth_addr src;
	uint16_t type;
} __attribute__((packed));

#define VLAN_HLEN 4

struct vlan_hdr {
	eth_addr dst;
	eth_addr src;
	uint16_t tpid;
	uint16_t tci;
	uint16_t type;
} __attribute__((packed));

#define OFF_ETYPE (2 * sizeof(eth_addr))

#endif
