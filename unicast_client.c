/**
 * @file unicast_client.c
 * @brief Unicast client implementation
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
#include <stdlib.h>

#include "port.h"
#include "port_private.h"
#include "print.h"
#include "unicast_client.h"

#define E2E_SYDY_MASK	(1 << ANNOUNCE | 1 << SYNC | 1 << DELAY_RESP)
#define P2P_SYDY_MASK	(1 << ANNOUNCE | 1 << SYNC)

static int attach_ack(struct ptp_message *msg, uint8_t message_type_flags)
{
	struct ack_cancel_unicast_xmit_tlv *ack;
	struct tlv_extra *extra;

	extra = msg_tlv_append(msg, sizeof(*ack));
	if (!extra) {
		return -1;
	}
	ack = (struct ack_cancel_unicast_xmit_tlv *) extra->tlv;
	ack->type = TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION;
	ack->length = sizeof(*ack) - sizeof(ack->type) - sizeof(ack->length);
	ack->message_type_flags = message_type_flags;

	return 0;
}

static int attach_request(struct ptp_message *msg, int log_period,
			  uint8_t message_type, int duration)
{
	struct request_unicast_xmit_tlv *req;
	struct tlv_extra *extra;

	extra = msg_tlv_append(msg, sizeof(*req));
	if (!extra) {
		return -1;
	}
	req = (struct request_unicast_xmit_tlv *) extra->tlv;
	req->type = TLV_REQUEST_UNICAST_TRANSMISSION;
	req->length = sizeof(*req) - sizeof(req->type) - sizeof(req->length);
	req->message_type = message_type << 4;
	req->logInterMessagePeriod = log_period;
	req->durationField = duration;

	return 0;
}

static int unicast_client_announce(struct port *p,
				   struct unicast_master_address *dst)
{
	struct ptp_message *msg;
	int err;

	msg = port_signaling_uc_construct(p, &dst->address, &dst->portIdentity);
	if (!msg) {
		return -1;
	}
	err = attach_request(msg, p->logAnnounceInterval, ANNOUNCE,
			     p->unicast_req_duration);
	if (err) {
		goto out;
	}
	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: signaling message failed", p->log_name);
	}
out:
	msg_put(msg);
	return err;
}

static struct unicast_master_address *unicast_client_ok(struct port *p,
							struct ptp_message *m)
{
	struct unicast_master_address *ucma;

	if (!unicast_client_enabled(p)) {
		return NULL;
	}
	STAILQ_FOREACH(ucma, &p->unicast_master_table->addrs, list) {
		if (addreq(transport_type(p->trp), &ucma->address, &m->address)) {
			break;
		}
	}
	if (!ucma) {
		pr_warning("%s: received rogue unicast grant or cancel",
			   p->log_name);
		return NULL;
	}
	return ucma;
}

static int unicast_client_peer_renew(struct port *p)
{
	struct unicast_master_address *peer;
	struct ptp_message *msg;
	struct timespec now;
	int err;

	if (!p->unicast_master_table->peer_name) {
		return 0;
	}
	err = clock_gettime(CLOCK_MONOTONIC, &now);
	if (err) {
		pr_err("clock_gettime failed: %m");
		return err;
	}
	peer = &p->unicast_master_table->peer_addr;
	if (now.tv_sec < peer->renewal_tmo) {
		return 0;
	}
	peer->renewal_tmo = 0;
	pr_debug("%s: time to renew P2P unicast subscription", p->log_name);

	msg = port_signaling_uc_construct(p, &peer->address, &peer->portIdentity);
	if (!msg) {
		return -1;
	}
	err = attach_request(msg, p->logPdelayReqInterval, PDELAY_RESP,
			     p->unicast_req_duration);
	if (err) {
		goto out;
	}
	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: P2P signaling message failed", p->log_name);
	}
out:
	msg_put(msg);
	return err;
}

static int unicast_client_renew(struct port *p,
				struct unicast_master_address *dst)
{
	struct ptp_message *msg;
	struct timespec now;
	int err;

	err = clock_gettime(CLOCK_MONOTONIC, &now);
	if (err) {
		pr_err("clock_gettime failed: %m");
		return err;
	}
	if (now.tv_sec < dst->renewal_tmo) {
		return 0;
	}
	dst->renewal_tmo = 0;
	pr_debug("%s: time to renew unicast subscriptions", p->log_name);

	msg = port_signaling_uc_construct(p, &dst->address, &dst->portIdentity);
	if (!msg) {
		return -1;
	}
	err = attach_request(msg, p->logAnnounceInterval, ANNOUNCE,
			     p->unicast_req_duration);
	if (err) {
		goto out;
	}

	if (dst->state == UC_HAVE_SYDY) {
		err = attach_request(msg, p->logSyncInterval, SYNC,
				     p->unicast_req_duration);
		if (err) {
			goto out;
		}
		if (p->delayMechanism != DM_P2P) {
			err = attach_request(msg, p->logMinDelayReqInterval,
					     DELAY_RESP,
					     p->unicast_req_duration);
			if (err) {
				goto out;
			}
		}
	}

	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: signaling message failed", p->log_name);
	}
out:
	msg_put(msg);
	return err;
}

static void unicast_client_set_renewal(struct port *p,
				       struct unicast_master_address *master,
				       long duration)
{
	struct timespec now;
	time_t tmo;

	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		pr_err("clock_gettime failed: %m");
		return;
	}
	duration = (3 * duration) / 4;
	tmo = now.tv_sec + duration;
	if (!master->renewal_tmo || tmo < master->renewal_tmo) {
		master->renewal_tmo = tmo;
		pr_debug("%s: renewal timeout at %lld", p->log_name, (long long)tmo);
	}
}

static int unicast_client_sydy(struct port *p,
			       struct unicast_master_address *dst)
{
	struct ptp_message *msg;
	int err;

	msg = port_signaling_uc_construct(p, &dst->address, &dst->portIdentity);
	if (!msg) {
		return -1;
	}
	err = attach_request(msg, p->logSyncInterval, SYNC,
			     p->unicast_req_duration);
	if (err) {
		goto out;
	}
	if (p->delayMechanism != DM_P2P) {
		err = attach_request(msg, p->logMinDelayReqInterval, DELAY_RESP,
				     p->unicast_req_duration);
		if (err) {
			goto out;
		}
	}
	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: signaling message failed", p->log_name);
	}
out:
	msg_put(msg);
	return err;
}

static void free_master_table(struct unicast_master_table *table)
{
	struct unicast_master_address *address;

	while ((address = STAILQ_FIRST(&table->addrs))) {
		STAILQ_REMOVE_HEAD(&table->addrs, list);
		free(address);
	}
	free(table->peer_name);
	free(table);
}

static struct unicast_master_table *
clone_master_table(struct unicast_master_table *table)
{
	struct unicast_master_address *address, *cloned_address;
	struct unicast_master_table *cloned_table;

	cloned_table = malloc(sizeof(*cloned_table));
	if (!cloned_table)
		return NULL;
	*cloned_table = *table;
	STAILQ_INIT(&cloned_table->addrs);
	memset(&cloned_table->list, 0, sizeof(cloned_table->list));
	if (table->peer_name)
		cloned_table->peer_name = strdup(table->peer_name);

	STAILQ_FOREACH(address, &table->addrs, list) {
		cloned_address = malloc(sizeof(*cloned_address));
		if (!cloned_address) {
			free_master_table(cloned_table);
			return NULL;
		}
		*cloned_address = *address;
		STAILQ_INSERT_TAIL(&cloned_table->addrs, cloned_address, list);
	}
	return cloned_table;
}

/* public methods */

int unicast_client_cancel(struct port *p, struct ptp_message *m,
			  struct tlv_extra *extra)
{
	struct cancel_unicast_xmit_tlv *cancel;
	struct unicast_master_address *ucma;
	struct ptp_message *msg;
	uint8_t mtype;
	int err;

	ucma = unicast_client_ok(p, m);
	if (!ucma) {
		return 0;
	}
	cancel = (struct cancel_unicast_xmit_tlv *) extra->tlv;
	mtype = cancel->message_type_flags >> 4;
	switch (mtype) {
	case ANNOUNCE:
	case SYNC:
	case DELAY_RESP:
		break;
	default:
		return 0;
	}
	if (cancel->message_type_flags & CANCEL_UNICAST_MAINTAIN_GRANT) {
		return 0;
	}
	pr_warning("%s: server unilaterally canceled unicast %s grant",
		   p->log_name, msg_type_string(mtype));

	ucma->state = unicast_fsm(ucma->state, UC_EV_CANCEL);
	ucma->granted &= ~(1 << mtype);

	/* Respond with ACK. */
	msg = port_signaling_uc_construct(p, &ucma->address, &ucma->portIdentity);
	if (!msg) {
		return -1;
	}
	err = attach_ack(msg, cancel->message_type_flags);
	if (err) {
		goto out;
	}
	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: signaling message failed", p->log_name);
	}
out:
	msg_put(msg);
	return err;
}

int unicast_client_initialize(struct port *p)
{
	struct unicast_master_address *master, *peer;
	struct config *cfg = clock_config(p->clock);
	struct unicast_master_table *table;
	int table_id;

	table_id = config_get_int(cfg, p->name, "unicast_master_table");
	if (!table_id) {
		return 0;
	}
	STAILQ_FOREACH(table, &cfg->unicast_master_tables, list) {
		if (table->table_index == table_id) {
			break;
		}
	}
	if (!table) {
		pr_err("%s: no table with id %d", p->log_name, table_id);
		return -1;
	}
	table = clone_master_table(table);
	if (!table) {
		pr_err("low memory");
		return -1;
	}
	peer = &table->peer_addr;
	if (table->peer_name && str2addr(transport_type(p->trp),
					 table->peer_name, &peer->address)) {
		pr_err("%s: bad peer address: %s",
		       p->log_name, table->peer_name);
		free_master_table(table);
		return -1;
	}
	STAILQ_FOREACH(master, &table->addrs, list) {
		if (master->type != transport_type(p->trp)) {
			pr_warning("%s: unicast master transport mismatch",
				   p->log_name);
		}
		if (p->delayMechanism == DM_P2P) {
			master->sydymsk = P2P_SYDY_MASK;
		} else {
			master->sydymsk = E2E_SYDY_MASK;
		}
	}
	table->port = portnum(p);
	p->unicast_master_table = table;
	p->unicast_req_duration =
		config_get_int(cfg, p->name, "unicast_req_duration");
	return 0;
}

void unicast_client_cleanup(struct port *p)
{
	if (p->unicast_master_table)
		free_master_table(p->unicast_master_table);
}

int unicast_client_enabled(struct port *p)
{
	return p->unicast_master_table ? 1 : 0;
}

void unicast_client_grant(struct port *p, struct ptp_message *m,
			  struct tlv_extra *extra)
{
	struct unicast_master_address *ucma;
	struct grant_unicast_xmit_tlv *g;
	int mtype;

	ucma = unicast_client_ok(p, m);
	if (!ucma) {
		return;
	}
	g = (struct grant_unicast_xmit_tlv *) extra->tlv;
	mtype = g->message_type >> 4;

	if (!g->durationField) {
		pr_warning("%s: unicast grant of %s rejected",
			   p->log_name, msg_type_string(mtype));
		if (mtype != PDELAY_RESP) {
			ucma->state = UC_WAIT;
		}
		return;
	}
	pr_debug("%s: unicast %s granted for %u sec",
		 p->log_name, msg_type_string(mtype), g->durationField);

	if (p->delayMechanism == DM_P2P) {
		switch (mtype) {
		case DELAY_RESP:
			return;
		case PDELAY_RESP:
			p->unicast_master_table->peer_addr.portIdentity =
				m->header.sourcePortIdentity;
			unicast_client_set_renewal(p,
				&p->unicast_master_table->peer_addr,
				g->durationField);
			p->logPdelayReqInterval = g->logInterMessagePeriod;
			return;
		default:
			break;
		}
	}

	ucma->granted |= 1 << mtype;

	switch (ucma->state) {
	case UC_WAIT:
		if (mtype == ANNOUNCE) {
			ucma->state = unicast_fsm(ucma->state, UC_EV_GRANT_ANN);
			ucma->portIdentity = m->header.sourcePortIdentity;
			unicast_client_set_renewal(p, ucma, g->durationField);
		}
		break;
	case UC_HAVE_ANN:
		break;
	case UC_NEED_SYDY:
		switch (mtype) {
		case DELAY_RESP:
			if ((ucma->granted & ucma->sydymsk) == ucma->sydymsk) {
				ucma->state = unicast_fsm(ucma->state,
							  UC_EV_GRANT_SYDY);
			}
			unicast_client_set_renewal(p, ucma, g->durationField);
			p->logMinDelayReqInterval = g->logInterMessagePeriod;
			break;
		case SYNC:
			if ((ucma->granted & ucma->sydymsk) == ucma->sydymsk) {
				ucma->state = unicast_fsm(ucma->state,
							  UC_EV_GRANT_SYDY);
			}
			unicast_client_set_renewal(p, ucma, g->durationField);
			clock_sync_interval(p->clock, g->logInterMessagePeriod);
			break;
		}
		break;
	case UC_HAVE_SYDY:
		switch (mtype) {
		case ANNOUNCE:
		case DELAY_RESP:
		case SYNC:
			unicast_client_set_renewal(p, ucma, g->durationField);
			break;
		}
		break;
	}
}

int unicast_client_set_tmo(struct port *p)
{
	return set_tmo_log(p->fda.fd[FD_UNICAST_REQ_TIMER], 1,
			   p->unicast_master_table->logQueryInterval);
}

void unicast_client_state_changed(struct port *p)
{
	struct unicast_master_address *ucma;
	struct PortIdentity pid;

	if (!unicast_client_enabled(p)) {
		return;
	}
	pid = clock_parent_identity(p->clock);

	STAILQ_FOREACH(ucma, &p->unicast_master_table->addrs, list) {
		if (pid_eq(&ucma->portIdentity, &pid)) {
			ucma->state = unicast_fsm(ucma->state, UC_EV_SELECTED);
		} else {
			ucma->state = unicast_fsm(ucma->state, UC_EV_UNSELECTED);
		}
	}
}

int unicast_client_timer(struct port *p)
{
	struct unicast_master_address *master;
	int err = 0;

	STAILQ_FOREACH(master, &p->unicast_master_table->addrs, list) {
		if (master->type != transport_type(p->trp)) {
			continue;
		}
		switch (master->state) {
		case UC_WAIT:
			err = unicast_client_announce(p, master);
			break;
		case UC_HAVE_ANN:
			err = unicast_client_renew(p, master);
			break;
		case UC_NEED_SYDY:
			err = unicast_client_sydy(p, master);
			break;
		case UC_HAVE_SYDY:
			err = unicast_client_renew(p, master);
			break;
		}
		if (p->delayMechanism == DM_P2P) {
			unicast_client_peer_renew(p);
		}
	}

	unicast_client_set_tmo(p);
	return err;
}
