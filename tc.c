/**
 * @file tc.c
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
#include "print.h"
#include "tc.h"
#include "tmv.h"

enum tc_match {
	TC_MISMATCH,
	TC_SYNC_FUP,
	TC_FUP_SYNC,
	TC_DELAY_REQRESP,
};

static TAILQ_HEAD(tc_pool, tc_txd) tc_pool = TAILQ_HEAD_INITIALIZER(tc_pool);

static int tc_match_delay(int ingress_port, struct ptp_message *resp,
			  struct tc_txd *txd);
static int tc_match_syfup(int ingress_port, struct ptp_message *msg,
			  struct tc_txd *txd);
static void tc_recycle(struct tc_txd *txd);

static struct tc_txd *tc_allocate(void)
{
	struct tc_txd *txd = TAILQ_FIRST(&tc_pool);

	if (txd) {
		TAILQ_REMOVE(&tc_pool, txd, list);
		memset(txd, 0, sizeof(*txd));
		return txd;
	}
	txd = calloc(1, sizeof(*txd));
	return txd;
}

static int tc_blocked(struct port *q, struct port *p, struct ptp_message *m)
{
	enum port_state s;

	if (q == p) {
		return 1;
	}
	if (portnum(p) == 0) {
		return 1;
	}
	if (!q->tc_spanning_tree) {
		return 0;
	}
	/* Forward frames in the wrong domain unconditionally. */
	if (m->header.domainNumber != clock_domain_number(p->clock)) {
		return 0;
	}
	/* Ingress state */
	s = port_state(q);
	switch (s) {
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_PASSIVE:
		return 1;
	case PS_MASTER:
	case PS_GRAND_MASTER:
		/* Delay_Req swims against the stream. */
		if (msg_type(m) != DELAY_REQ) {
			return 1;
		}
		break;
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		break;
	}
	/* Egress state */
	s = port_state(p);
	switch (s) {
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_PASSIVE:
		return 1;
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		/* Delay_Req swims against the stream. */
		if (msg_type(m) != DELAY_REQ) {
			return 1;
		}
		break;
	case PS_MASTER:
	case PS_GRAND_MASTER:
		/* No use forwarding Delay_Req out the wrong port. */
		if (msg_type(m) == DELAY_REQ) {
			return 1;
		}
		break;
	}
	return 0;
}

static void tc_complete_request(struct port *q, struct port *p,
				struct ptp_message *req, tmv_t residence)
{
	struct tc_txd *txd = tc_allocate();
	if (!txd) {
		port_dispatch(p, EV_FAULT_DETECTED, 0);
		return;
	}
#ifdef DEBUG
	pr_err("stash delay request from %s to %s seqid %hu residence %lu",
	       q->log_name, p->log_name, ntohs(req->header.sequenceId),
	       (unsigned long) tmv_to_nanoseconds(residence));
#endif
	msg_get(req);
	txd->msg = req;
	txd->residence = residence;
	txd->ingress_port = portnum(q);
	TAILQ_INSERT_TAIL(&p->tc_transmitted, txd, list);
}

static void tc_complete_response(struct port *q, struct port *p,
				 struct ptp_message *resp, tmv_t residence)
{
	enum tc_match type = TC_MISMATCH;
	struct tc_txd *txd;
	Integer64 c1, c2;
	int cnt;

#ifdef DEBUG
	pr_err("complete delay response from %s to %s seqid %hu",
	       q->log_name, p->log_name, ntohs(resp->header.sequenceId));
#endif
	TAILQ_FOREACH(txd, &q->tc_transmitted, list) {
		type = tc_match_delay(portnum(p), resp, txd);
		if (type == TC_DELAY_REQRESP) {
			residence = txd->residence;
			break;
		}
	}
	if (type != TC_DELAY_REQRESP) {
		return;
	}
	c1 = net2host64(resp->header.correction);
	c2 = c1 + tmv_to_TimeInterval(residence);
	resp->header.correction = host2net64(c2);
	cnt = transport_send(p->trp, &p->fda, TRANS_GENERAL, resp);
	if (cnt <= 0) {
		pr_err("tc failed to forward response on %s", p->log_name);
		port_dispatch(p, EV_FAULT_DETECTED, 0);
	}
	/* Restore original correction value for next egress port. */
	resp->header.correction = host2net64(c1);
	TAILQ_REMOVE(&q->tc_transmitted, txd, list);
	msg_put(txd->msg);
	tc_recycle(txd);
}

static void tc_complete_syfup(struct port *q, struct port *p,
			      struct ptp_message *msg, tmv_t residence)
{
	enum tc_match type = TC_MISMATCH;
	struct ptp_message *fup;
	struct tc_txd *txd;
	Integer64 c1, c2;
	int cnt;

	TAILQ_FOREACH(txd, &p->tc_transmitted, list) {
		type = tc_match_syfup(portnum(q), msg, txd);
		switch (type) {
		case TC_MISMATCH:
			break;
		case TC_SYNC_FUP:
			fup = msg;
			residence = txd->residence;
			break;
		case TC_FUP_SYNC:
			fup = txd->msg;
			break;
		case TC_DELAY_REQRESP:
			pr_err("tc: unexpected match of delay request - sync!");
			return;
		}
		if (type != TC_MISMATCH) {
			break;
		}
	}

	if (type == TC_MISMATCH) {
		txd = tc_allocate();
		if (!txd) {
			port_dispatch(p, EV_FAULT_DETECTED, 0);
			return;
		}
		msg_get(msg);
		txd->msg = msg;
		txd->residence = residence;
		txd->ingress_port = portnum(q);
		TAILQ_INSERT_TAIL(&p->tc_transmitted, txd, list);
		return;
	}

	c1 = net2host64(fup->header.correction);
	c2 = c1 + tmv_to_TimeInterval(residence);
	c2 += tmv_to_TimeInterval(q->peer_delay);
	c2 += q->asymmetry;
	fup->header.correction = host2net64(c2);
	cnt = transport_send(p->trp, &p->fda, TRANS_GENERAL, fup);
	if (cnt <= 0) {
		pr_err("tc failed to forward follow up on %s", p->log_name);
		port_dispatch(p, EV_FAULT_DETECTED, 0);
	}
	/* Restore original correction value for next egress port. */
	fup->header.correction = host2net64(c1);
	TAILQ_REMOVE(&p->tc_transmitted, txd, list);
	msg_put(txd->msg);
	tc_recycle(txd);
}

static void tc_complete(struct port *q, struct port *p,
			struct ptp_message *msg, tmv_t residence)
{
	switch (msg_type(msg)) {
	case SYNC:
	case FOLLOW_UP:
		tc_complete_syfup(q, p, msg, residence);
		break;
	case DELAY_REQ:
		tc_complete_request(q, p, msg, residence);
		break;
	case DELAY_RESP:
		tc_complete_response(q, p, msg, residence);
		break;
	}
}

static int tc_current(struct ptp_message *m, struct timespec now)
{
	int64_t t1, t2, tmo;

	tmo = 1LL * NSEC2SEC;
	t1 = m->ts.host.tv_sec * NSEC2SEC + m->ts.host.tv_nsec;
	t2 = now.tv_sec * NSEC2SEC + now.tv_nsec;

	return t2 - t1 < tmo;
}

static int tc_fwd_event(struct port *q, struct ptp_message *msg)
{
	tmv_t egress, ingress = msg->hwts.ts, residence;
	struct port *p;
	int cnt, err;
	double rr;

	clock_gettime(CLOCK_MONOTONIC, &msg->ts.host);

	/* First send the event message out. */
	for (p = clock_first_port(q->clock); p; p = LIST_NEXT(p, list)) {
		if (tc_blocked(q, p, msg)) {
			continue;
		}
		cnt = transport_send(p->trp, &p->fda, TRANS_DEFER_EVENT, msg);
		if (cnt <= 0) {
			pr_err("failed to forward event from %s to %s",
				q->log_name, p->log_name);
			port_dispatch(p, EV_FAULT_DETECTED, 0);
		}
	}

	/* Go back and gather the transmit time stamps. */
	for (p = clock_first_port(q->clock); p; p = LIST_NEXT(p, list)) {
		if (tc_blocked(q, p, msg)) {
			continue;
		}
		err = transport_txts(&p->fda, msg);
		if (err || !msg_sots_valid(msg)) {
			pr_err("failed to fetch txts on %s to %s event",
				q->log_name, p->log_name);
			port_dispatch(p, EV_FAULT_DETECTED, 0);
			continue;
		}
		ts_add(&msg->hwts.ts, p->tx_timestamp_offset);
		egress = msg->hwts.ts;
		residence = tmv_sub(egress, ingress);
		rr = clock_rate_ratio(q->clock);
		if (rr != 1.0) {
			residence = dbl_tmv(tmv_dbl(residence) * rr);
		}
		tc_complete(q, p, msg, residence);
	}

	return 0;
}

static int tc_match_delay(int ingress_port, struct ptp_message *resp,
			  struct tc_txd *txd)
{
	struct ptp_message *req = txd->msg;

	if (ingress_port != txd->ingress_port) {
		return TC_MISMATCH;
	}
	if (req->header.sequenceId != resp->header.sequenceId) {
		return TC_MISMATCH;
	}
	if (!pid_eq(&req->header.sourcePortIdentity,
		    &resp->delay_resp.requestingPortIdentity)) {
		return TC_MISMATCH;
	}
	if (msg_type(req) == DELAY_REQ && msg_type(resp) == DELAY_RESP) {
		return TC_DELAY_REQRESP;
	}
	return TC_MISMATCH;
}

static int tc_match_syfup(int ingress_port, struct ptp_message *msg,
			  struct tc_txd *txd)
{
	if (ingress_port != txd->ingress_port) {
		return TC_MISMATCH;
	}
	if (msg->header.sequenceId != txd->msg->header.sequenceId) {
		return TC_MISMATCH;
	}
	if (!source_pid_eq(msg, txd->msg)) {
		return TC_MISMATCH;
	}
	if (msg_type(txd->msg) == SYNC && msg_type(msg) == FOLLOW_UP) {
		return TC_SYNC_FUP;
	}
	if (msg_type(txd->msg) == FOLLOW_UP && msg_type(msg) == SYNC) {
		return TC_FUP_SYNC;
	}
	return TC_MISMATCH;
}

static void tc_recycle(struct tc_txd *txd)
{
	TAILQ_INSERT_HEAD(&tc_pool, txd, list);
}

/* public methods */

void tc_cleanup(void)
{
	struct tc_txd *txd;

	while ((txd = TAILQ_FIRST(&tc_pool)) != NULL) {
		TAILQ_REMOVE(&tc_pool, txd, list);
		free(txd);
	}
}

void tc_flush(struct port *q)
{
	struct tc_txd *txd;

	while ((txd = TAILQ_FIRST(&q->tc_transmitted)) != NULL) {
		TAILQ_REMOVE(&q->tc_transmitted, txd, list);
		msg_put(txd->msg);
		tc_recycle(txd);
	}
}

int tc_forward(struct port *q, struct ptp_message *msg)
{
	uint16_t steps_removed;
	struct port *p;
	int cnt;

	if (q->tc_spanning_tree && msg_type(msg) == ANNOUNCE) {
		steps_removed = ntohs(msg->announce.stepsRemoved);
		msg->announce.stepsRemoved = htons(1 + steps_removed);
	}

	for (p = clock_first_port(q->clock); p; p = LIST_NEXT(p, list)) {
		if (tc_blocked(q, p, msg)) {
			continue;
		}
		cnt = transport_send(p->trp, &p->fda, TRANS_GENERAL, msg);
		if (cnt <= 0) {
			pr_err("tc failed to forward message on %s",
			       p->log_name);
			port_dispatch(p, EV_FAULT_DETECTED, 0);
		}
	}
	return 0;
}

int tc_fwd_folup(struct port *q, struct ptp_message *msg)
{
	struct port *p;

	clock_gettime(CLOCK_MONOTONIC, &msg->ts.host);

	for (p = clock_first_port(q->clock); p; p = LIST_NEXT(p, list)) {
		if (tc_blocked(q, p, msg)) {
			continue;
		}
		tc_complete(q, p, msg, tmv_zero());
	}
	return 0;
}

int tc_fwd_request(struct port *q, struct ptp_message *msg)
{
	return tc_fwd_event(q, msg);
}

int tc_fwd_response(struct port *q, struct ptp_message *msg)
{
	struct port *p;

	clock_gettime(CLOCK_MONOTONIC, &msg->ts.host);

	for (p = clock_first_port(q->clock); p; p = LIST_NEXT(p, list)) {
		if (tc_blocked(q, p, msg)) {
			continue;
		}
		tc_complete(q, p, msg, tmv_zero());
	}
	return 0;
}

int tc_fwd_sync(struct port *q, struct ptp_message *msg)
{
	struct ptp_message *fup = NULL;
	int err;

	if (one_step(msg)) {
		fup = msg_allocate();
		if (!fup) {
			return -1;
		}
		fup->header.tsmt               = FOLLOW_UP | (msg->header.tsmt & 0xf0);
		fup->header.ver                = msg->header.ver;
		fup->header.messageLength      = htons(sizeof(struct follow_up_msg));
		fup->header.domainNumber       = msg->header.domainNumber;
		fup->header.sourcePortIdentity = msg->header.sourcePortIdentity;
		fup->header.sequenceId         = msg->header.sequenceId;
		fup->header.control            = CTL_FOLLOW_UP;
		fup->header.logMessageInterval = msg->header.logMessageInterval;
		fup->follow_up.preciseOriginTimestamp = msg->sync.originTimestamp;
		msg->header.flagField[0]      |= TWO_STEP;
	}
	err = tc_fwd_event(q, msg);
	if (err) {
		return err;
	}
	if (fup) {
		err = tc_fwd_folup(q, fup);
		msg_put(fup);
	}
	return err;
}

int tc_ignore(struct port *p, struct ptp_message *m)
{
	struct ClockIdentity c1, c2;

	if (p->match_transport_specific &&
	    msg_transport_specific(m) != p->transportSpecific) {
		return 1;
	}
	if (pid_eq(&m->header.sourcePortIdentity, &p->portIdentity)) {
		return 1;
	}
	if (m->header.domainNumber != clock_domain_number(p->clock)) {
		return 1;
	}

	c1 = clock_identity(p->clock);
	c2 = m->header.sourcePortIdentity.clockIdentity;

	if (cid_eq(&c1, &c2)) {
		return 1;
	}
	return 0;
}

void tc_prune(struct port *q)
{
	struct timespec now;
	struct tc_txd *txd;

	clock_gettime(CLOCK_MONOTONIC, &now);

	while ((txd = TAILQ_FIRST(&q->tc_transmitted)) != NULL) {
		if (tc_current(txd->msg, now)) {
			break;
		}
		TAILQ_REMOVE(&q->tc_transmitted, txd, list);
		msg_put(txd->msg);
		tc_recycle(txd);
	}
}
