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

#include "test.h"

int transport_close(struct transport *t, struct fdarray *fda)
{
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	return t->close(t, fda);
}

int transport_open(struct transport *t, struct interface *iface,
		   struct fdarray *fda, enum timestamp_type tt)
{
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	return t->open(t, iface, fda, tt);
}

int transport_recv(struct transport *t, int fd, struct ptp_message *msg)
{
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	return t->recv(t, fd, msg, sizeof(msg->data), &msg->address, &msg->hwts);
}

int transport_send(struct transport *t, struct fdarray *fda,
		   enum transport_event event, struct ptp_message *msg)
{
	int len = ntohs(msg->header.messageLength);
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
#if TRAN_SEND
	fprintf(stderr, "transport_send-->msg_header_len:%d\n", len);
	fprintf(stderr, "transport_send-->event:%d\n", event);
#endif
	return t->send(t, fda, event, 0, msg, len, NULL, &msg->hwts);
}

int transport_peer(struct transport *t, struct fdarray *fda,
		   enum transport_event event, struct ptp_message *msg)
{
	int len = ntohs(msg->header.messageLength);
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif

	return t->send(t, fda, event, 1, msg, len, NULL, &msg->hwts);
}

int transport_sendto(struct transport *t, struct fdarray *fda,
		     enum transport_event event, struct ptp_message *msg)
{
	int len = ntohs(msg->header.messageLength);
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif

	return t->send(t, fda, event, 0, msg, len, &msg->address, &msg->hwts);
}

int transport_txts(struct fdarray *fda,
		   struct ptp_message *msg)
{
	int cnt, len = ntohs(msg->header.messageLength);
	struct hw_timestamp *hwts = &msg->hwts;
	unsigned char pkt[1600];

#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	cnt = sk_receive(fda->fd[FD_EVENT], pkt, len, NULL, hwts, MSG_ERRQUEUE);
	return cnt > 0 ? 0 : cnt;
}

int transport_physical_addr(struct transport *t, uint8_t *addr)
{
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	if (t->physical_addr) {
		return t->physical_addr(t, addr);
	}
	return 0;
}

int transport_protocol_addr(struct transport *t, uint8_t *addr)
{
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	if (t->protocol_addr) {
		return t->protocol_addr(t, addr);
	}
	return 0;
}

enum transport_type transport_type(struct transport *t)
{
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	return t->type;
}

struct transport *transport_create(struct config *cfg,
				   enum transport_type type)
{
	struct transport *t = NULL;
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
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
#if TRAN
	fprintf(stderr, "%s\n", __func__);
#endif
	t->release(t);
}
