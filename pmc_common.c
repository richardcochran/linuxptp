/**
 * @file pmc_common.c
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note Copyright (C) 2013 Miroslav Lichvar <mlichvar@redhat.com>
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
#include <string.h>
#include <stdlib.h>

#include "print.h"
#include "tlv.h"
#include "transport.h"
#include "util.h"
#include "pmc_common.h"

struct pmc {
	UInteger16 sequence_id;
	UInteger8 boundary_hops;
	UInteger8 domain_number;
	UInteger8 transport_specific;
	struct PortIdentity port_identity;

	struct transport *transport;
	struct fdarray fdarray;
};

struct pmc *pmc_create(enum transport_type transport_type, char *iface_name,
		       UInteger8 boundary_hops, UInteger8 domain_number,
		       UInteger8 transport_specific)
{
	struct pmc *pmc;

	pmc = calloc(1, sizeof *pmc);
	if (!pmc)
		return NULL;

	if (transport_type != TRANS_UDS &&
	    generate_clock_identity(&pmc->port_identity.clockIdentity,
				    iface_name)) {
		pr_err("failed to generate a clock identity");
		goto failed;
	}

	pmc->port_identity.portNumber = 1;
	pmc->boundary_hops = boundary_hops;
	pmc->domain_number = domain_number;
	pmc->transport_specific = transport_specific;

	pmc->transport = transport_create(transport_type);
	if (!pmc->transport) {
		pr_err("failed to create transport");
		goto failed;
	}
	if (transport_open(pmc->transport, iface_name,
			   &pmc->fdarray, TS_SOFTWARE)) {
		pr_err("failed to open transport");
		goto failed;
	}

	return pmc;

failed:
	if (pmc->transport)
		transport_destroy(pmc->transport);
	free(pmc);
	return NULL;
}

void pmc_destroy(struct pmc *pmc)
{
	transport_close(pmc->transport, &pmc->fdarray);
	transport_destroy(pmc->transport);
	free(pmc);
}

static struct ptp_message *pmc_message(struct pmc *pmc, uint8_t action)
{
	struct ptp_message *msg;
	int pdulen;

	msg = msg_allocate();
	if (!msg)
		return NULL;

	pdulen = sizeof(struct management_msg);
	msg->hwts.type = TS_SOFTWARE;

	msg->header.tsmt               = MANAGEMENT | pmc->transport_specific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = pmc->domain_number;
	msg->header.sourcePortIdentity = pmc->port_identity;
	msg->header.sequenceId         = pmc->sequence_id++;
	msg->header.control            = CTL_MANAGEMENT;
	msg->header.logMessageInterval = 0x7f;

	memset(&msg->management.targetPortIdentity, 0xff,
	       sizeof(msg->management.targetPortIdentity));
	msg->management.startingBoundaryHops = pmc->boundary_hops;
	msg->management.boundaryHops = pmc->boundary_hops;
	msg->management.flags = action;

	return msg;
}

static int pmc_send(struct pmc *pmc, struct ptp_message *msg, int pdulen)
{
	int cnt, err;
	err = msg_pre_send(msg);
	if (err) {
		pr_err("msg_pre_send failed");
		return -1;
	}
	cnt = transport_send(pmc->transport, &pmc->fdarray, 0,
			     msg, pdulen, &msg->hwts);
	if (cnt < 0) {
		pr_err("failed to send message");
		return -1;
	}
	return 0;
}

int pmc_get_transport_fd(struct pmc *pmc)
{
	return pmc->fdarray.fd[FD_GENERAL];
}

int pmc_send_get_action(struct pmc *pmc, int id)
{
	int pdulen;
	struct ptp_message *msg;
	struct management_tlv *mgt;
	msg = pmc_message(pmc, GET);
	if (!msg) {
		return -1;
	}
	mgt = (struct management_tlv *) msg->management.suffix;
	mgt->type = TLV_MANAGEMENT;
	mgt->length = 2;
	mgt->id = id;
	pdulen = msg->header.messageLength + sizeof(*mgt);
	msg->header.messageLength = pdulen;
	msg->tlv_count = 1;
	pmc_send(pmc, msg, pdulen);
	msg_put(msg);

	return 0;
}

int pmc_send_set_action(struct pmc *pmc, int id, void *data, int datasize)
{
	int pdulen;
	struct ptp_message *msg;
	struct management_tlv *mgt;
	msg = pmc_message(pmc, SET);
	if (!msg) {
		return -1;
	}
	mgt = (struct management_tlv *) msg->management.suffix;
	mgt->type = TLV_MANAGEMENT;
	mgt->length = 2 + datasize;
	mgt->id = id;
	memcpy(mgt->data, data, datasize);
	pdulen = msg->header.messageLength + sizeof(*mgt) + datasize;
	msg->header.messageLength = pdulen;
	msg->tlv_count = 1;
	pmc_send(pmc, msg, pdulen);
	msg_put(msg);

	return 0;
}

struct ptp_message *pmc_recv(struct pmc *pmc)
{
	struct ptp_message *msg;
	int cnt, err;

	msg = msg_allocate();
	if (!msg) {
		pr_err("low memory");
		return NULL;
	}
	msg->hwts.type = TS_SOFTWARE;
	cnt = transport_recv(pmc->transport, pmc_get_transport_fd(pmc),
			     msg, sizeof(msg->data), &msg->hwts);
	if (cnt <= 0) {
		pr_err("recv message failed");
		goto failed;
	}
	err = msg_post_recv(msg, cnt);
	if (err) {
		switch (err) {
		case -EBADMSG:
			pr_err("bad message");
			break;
		case -ETIME:
			pr_err("received %s without timestamp",
					msg_type_string(msg_type(msg)));
			break;
		case -EPROTO:
			pr_debug("ignoring message");
		}
		goto failed;
	}

	return msg;
failed:
	msg_put(msg);
	return NULL;
}
