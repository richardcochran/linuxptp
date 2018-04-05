/**
 * @file port_signaling.c
 * @brief Implements signaling messages
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
#include "port_private.h"
#include "unicast_client.h"
#include "unicast_service.h"

struct ptp_message *port_signaling_construct(struct port *p,
					     struct address *address,
					     struct PortIdentity *tpid)
{
	struct ptp_message *msg;

	msg = msg_allocate();
	if (!msg) {
		return NULL;
	}
	msg->hwts.type                 = p->timestamping;
	msg->header.tsmt               = SIGNALING | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct signaling_msg);
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.signaling++;
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = 0x7F;
	msg->signaling.targetPortIdentity = *tpid;
	msg->header.flagField[0] |= UNICAST;
	msg->address = *address;

	return msg;
}

int process_signaling(struct port *p, struct ptp_message *m)
{
	struct tlv_extra *extra;
	int err = 0, result;

	switch (p->state) {
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
		return 0;
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_MASTER:
	case PS_GRAND_MASTER:
	case PS_PASSIVE:
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		break;
	}

	TAILQ_FOREACH(extra, &m->tlv_list, list) {
		switch (extra->tlv->type) {
		case TLV_REQUEST_UNICAST_TRANSMISSION:
			result = unicast_service_add(p, m, extra);
			switch (result) {
			case SERVICE_GRANTED:
				err = unicast_service_grant(p, m, extra);
				break;
			case SERVICE_DENIED:
				err = unicast_service_deny(p, m, extra);
				break;
			case SERVICE_DISABLED:
			default:
				break;
			}
			break;

		case TLV_GRANT_UNICAST_TRANSMISSION:
			unicast_client_grant(p, m, extra);
			break;

		case TLV_CANCEL_UNICAST_TRANSMISSION:
			err = unicast_client_cancel(p, m, extra);
			unicast_service_remove(p, m, extra);
			break;

		case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
			break;
		}
	}
	return err;
}
