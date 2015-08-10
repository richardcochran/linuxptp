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

#include <arpa/inet.h>

#include "transport.h"
#include "transport_private.h"
#include "raw.h"
#include "udp.h"
#include "udp6.h"
#include "uds.h"

int transport_close(struct transport *t, struct fdarray *fda)
{
	return t->close(t, fda);
}

int transport_open(struct transport *t, const char *name,
		   struct fdarray *fda, enum timestamp_type tt)
{
	return t->open(t, name, fda, tt);
}

int transport_recv(struct transport *t, int fd, struct ptp_message *msg)
{
	return t->recv(t, fd, msg, sizeof(msg->data), &msg->address, &msg->hwts);
}

int transport_send(struct transport *t, struct fdarray *fda, int event,
		   struct ptp_message *msg)
{
	int len = ntohs(msg->header.messageLength);

	return t->send(t, fda, event, 0, msg, len, NULL, &msg->hwts);
}

int transport_peer(struct transport *t, struct fdarray *fda, int event,
		   struct ptp_message *msg)
{
	int len = ntohs(msg->header.messageLength);

	return t->send(t, fda, event, 1, msg, len, NULL, &msg->hwts);
}

int transport_sendto(struct transport *t, struct fdarray *fda, int event,
		     struct ptp_message *msg)
{
	int len = ntohs(msg->header.messageLength);

	return t->send(t, fda, event, 0, msg, len, &msg->address, &msg->hwts);
}

int transport_physical_addr(struct transport *t, uint8_t *addr)
{
	if (t->physical_addr) {
		return t->physical_addr(t, addr);
	}
	return 0;
}

int transport_protocol_addr(struct transport *t, uint8_t *addr)
{
	if (t->protocol_addr) {
		return t->protocol_addr(t, addr);
	}
	return 0;
}

enum transport_type transport_type(struct transport *t)
{
	return t->type;
}

struct transport *transport_create(struct config *cfg,
				   enum transport_type type)
{
	struct transport *t = NULL;
	switch (type) {
	case TRANS_UDS:
		t = uds_transport_create();
		break;
	case TRANS_UDP_IPV4:
		t = udp_transport_create();
		break;
	case TRANS_UDP_IPV6:
		t = udp6_transport_create();
		break;
	case TRANS_IEEE_802_3:
		t = raw_transport_create();
		break;
	case TRANS_DEVICENET:
	case TRANS_CONTROLNET:
	case TRANS_PROFINET:
		break;
	}
	if (t) {
		t->type = type;
		t->cfg = cfg;
	}
	return t;
}

void transport_destroy(struct transport *t)
{
	t->release(t);
}
