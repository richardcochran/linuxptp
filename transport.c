/**
 * @file transport.c
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

#include "transport.h"
#include "udp.h"

static struct transport udp = {
	.close = udp_close,
	.open  = udp_open,
	.recv  = udp_recv,
	.send  = udp_send,
};

struct transport *transport_find(enum transport_type type)
{
	switch (type) {
	case TRANS_UDP_IPV4:
		return &udp;
	case TRANS_UDP_IPV6:
	case TRANS_IEEE_802_3:
	case TRANS_DEVICENET:
	case TRANS_CONTROLNET:
	case TRANS_PROFINET:
		break;
	}
	return NULL;
}
