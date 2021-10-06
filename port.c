/**
 * @file port.c
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
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>
#include <net/if.h>

#include "bmc.h"
#include "clock.h"
#include "designated_fsm.h"
#include "filter.h"
#include "missing.h"
#include "msg.h"
#include "phc.h"
#include "port.h"
#include "port_private.h"
#include "print.h"
#include "rtnl.h"
#include "sk.h"
#include "tc.h"
#include "tlv.h"
#include "tmv.h"
#include "tsproc.h"
#include "unicast_client.h"
#include "unicast_service.h"
#include "util.h"

#define ALLOWED_LOST_RESPONSES 3
#define ANNOUNCE_SPAN 1

enum syfu_event {
	SYNC_MISMATCH,
	SYNC_MATCH,
	FUP_MISMATCH,
	FUP_MATCH,
};

static int port_is_ieee8021as(struct port *p);
static int port_is_uds(struct port *p);
static void port_nrate_initialize(struct port *p);

static int announce_compare(struct ptp_message *m1, struct ptp_message *m2)
{
	struct announce_msg *a = &m1->announce, *b = &m2->announce;
	int len =
		sizeof(a->grandmasterPriority1) +
		sizeof(a->grandmasterClockQuality) +
		sizeof(a->grandmasterPriority2) +
		sizeof(a->grandmasterIdentity) +
		sizeof(a->stepsRemoved);

	return memcmp(&a->grandmasterPriority1, &b->grandmasterPriority1, len);
}

static void announce_to_dataset(struct ptp_message *m, struct port *p,
				struct dataset *out)
{
	struct announce_msg *a = &m->announce;
	out->priority1    = a->grandmasterPriority1;
	out->identity     = a->grandmasterIdentity;
	out->quality      = a->grandmasterClockQuality;
	out->priority2    = a->grandmasterPriority2;
	out->localPriority = p->localPriority;
	out->stepsRemoved = a->stepsRemoved;
	out->sender       = m->header.sourcePortIdentity;
	out->receiver     = p->portIdentity;
}

int clear_fault_asap(struct fault_interval *faint)
{
	switch (faint->type) {
	case FTMO_LINEAR_SECONDS:
		return faint->val == 0 ? 1 : 0;
	case FTMO_LOG2_SECONDS:
		return faint->val == FRI_ASAP ? 1 : 0;
	case FTMO_CNT:
		return 0;
	}
	return 0;
}

static int check_source_identity(struct port *p, struct ptp_message *m)
{
	struct PortIdentity master;

	if (p->ignore_source_id) {
		return 0;
	}
	master = clock_parent_identity(p->clock);
	return pid_eq(&master, &m->header.sourcePortIdentity) ? 0 : -1;
}

static void extract_address(struct ptp_message *m, struct PortAddress *paddr)
{
	int len = 0;

	switch (paddr->networkProtocol) {
	case TRANS_UDP_IPV4:
		len = sizeof(m->address.sin.sin_addr.s_addr);
		memcpy(paddr->address, &m->address.sin.sin_addr.s_addr, len);
		break;
	case TRANS_UDP_IPV6:
		len = sizeof(m->address.sin6.sin6_addr.s6_addr);
		memcpy(paddr->address, &m->address.sin6.sin6_addr.s6_addr, len);
		break;
	case TRANS_IEEE_802_3:
		len = MAC_LEN;
		memcpy(paddr->address, &m->address.sll.sll_addr, len);
		break;
	default:
		return;
	}
	paddr->addressLength = len;
}

static int msg_current(struct ptp_message *m, struct timespec now)
{
	int64_t t1, t2, tmo;

	t1 = m->ts.host.tv_sec * NSEC2SEC + m->ts.host.tv_nsec;
	t2 = now.tv_sec * NSEC2SEC + now.tv_nsec;

	if (m->header.logMessageInterval <= -31) {
		tmo = 0;
	} else if (m->header.logMessageInterval >= 31) {
		tmo = INT64_MAX;
	} else if (m->header.logMessageInterval < 0) {
		tmo = 4LL * NSEC2SEC / (1 << -m->header.logMessageInterval);
	} else {
		tmo = 4LL * (1 << m->header.logMessageInterval) * NSEC2SEC;
	}

	return t2 - t1 < tmo;
}

static int msg_source_equal(struct ptp_message *m1, struct foreign_clock *fc)
{
	struct PortIdentity *id1, *id2;

	if (!fc) {
		return 0;
	}

	id1 = &m1->header.sourcePortIdentity;
	id2 = &fc->dataset.sender;
	return 0 == memcmp(id1, id2, sizeof(*id1));
}

int source_pid_eq(struct ptp_message *m1, struct ptp_message *m2)
{
	return pid_eq(&m1->header.sourcePortIdentity,
		      &m2->header.sourcePortIdentity);
}

enum fault_type last_fault_type(struct port *port)
{
	return port->last_fault_type;
}

void fault_interval(struct port *port, enum fault_type ft,
		    struct fault_interval *i)
{
	i->type = port->flt_interval_pertype[ft].type;
	i->val = port->flt_interval_pertype[ft].val;
}

int port_fault_fd(struct port *port)
{
	return port->fault_fd;
}

struct fdarray *port_fda(struct port *port)
{
	return &port->fda;
}

int set_tmo_log(int fd, unsigned int scale, int log_seconds)
{
	struct itimerspec tmo = {
		{0, 0}, {0, 0}
	};
	uint64_t ns;
	int i;

	if (log_seconds < 0) {

		log_seconds *= -1;
		for (i = 1, ns = scale * 500000000ULL; i < log_seconds; i++) {
			ns >>= 1;
		}
		tmo.it_value.tv_nsec = ns;

		while (tmo.it_value.tv_nsec >= NS_PER_SEC) {
			tmo.it_value.tv_nsec -= NS_PER_SEC;
			tmo.it_value.tv_sec++;
		}

	} else
		tmo.it_value.tv_sec = scale * (1 << log_seconds);

	return timerfd_settime(fd, 0, &tmo, NULL);
}

int set_tmo_lin(int fd, int seconds)
{
	struct itimerspec tmo = {
		{0, 0}, {0, 0}
	};

	tmo.it_value.tv_sec = seconds;
	return timerfd_settime(fd, 0, &tmo, NULL);
}

int set_tmo_random(int fd, int min, int span, int log_seconds)
{
	uint64_t value_ns, min_ns, span_ns;
	struct itimerspec tmo = {
		{0, 0}, {0, 0}
	};

	if (log_seconds >= 0) {
		min_ns = min * NS_PER_SEC << log_seconds;
		span_ns = span * NS_PER_SEC << log_seconds;
	} else {
		min_ns = min * NS_PER_SEC >> -log_seconds;
		span_ns = span * NS_PER_SEC >> -log_seconds;
	}

	value_ns = min_ns + (span_ns * (random() % (1 << 15) + 1) >> 15);

	tmo.it_value.tv_sec = value_ns / NS_PER_SEC;
	tmo.it_value.tv_nsec = value_ns % NS_PER_SEC;

	return timerfd_settime(fd, 0, &tmo, NULL);
}

int port_set_fault_timer_log(struct port *port,
			     unsigned int scale, int log_seconds)
{
	return set_tmo_log(port->fault_fd, scale, log_seconds);
}

int port_set_fault_timer_lin(struct port *port, int seconds)
{
	return set_tmo_lin(port->fault_fd, seconds);
}

void fc_clear(struct foreign_clock *fc)
{
	struct ptp_message *m;

	while (fc->n_messages) {
		m = TAILQ_LAST(&fc->messages, messages);
		TAILQ_REMOVE(&fc->messages, m, list);
		fc->n_messages--;
		msg_put(m);
	}
}

static void fc_prune(struct foreign_clock *fc)
{
	struct timespec now;
	struct ptp_message *m;

	clock_gettime(CLOCK_MONOTONIC, &now);

	while (fc->n_messages > FOREIGN_MASTER_THRESHOLD) {
		m = TAILQ_LAST(&fc->messages, messages);
		TAILQ_REMOVE(&fc->messages, m, list);
		fc->n_messages--;
		msg_put(m);
	}

	while (!TAILQ_EMPTY(&fc->messages)) {
		m = TAILQ_LAST(&fc->messages, messages);
		if (msg_current(m, now))
			break;
		TAILQ_REMOVE(&fc->messages, m, list);
		fc->n_messages--;
		msg_put(m);
	}
}

static int delay_req_current(struct ptp_message *m, struct timespec now)
{
	int64_t t1, t2, tmo = 5 * NSEC2SEC;

	t1 = m->ts.host.tv_sec * NSEC2SEC + m->ts.host.tv_nsec;
	t2 = now.tv_sec * NSEC2SEC + now.tv_nsec;

	return t2 - t1 < tmo;
}

void delay_req_prune(struct port *p)
{
	struct timespec now;
	struct ptp_message *m;
	clock_gettime(CLOCK_MONOTONIC, &now);

	while (!TAILQ_EMPTY(&p->delay_req)) {
		m = TAILQ_LAST(&p->delay_req, delay_req);
		if (delay_req_current(m, now)) {
			break;
		}
		TAILQ_REMOVE(&p->delay_req, m, list);
		msg_put(m);
	}
}

void ts_add(tmv_t *ts, Integer64 correction)
{
	if (!correction) {
		return;
	}
	*ts = tmv_add(*ts, correction_to_tmv(correction));
}

/*
 * Returns non-zero if the announce message is different than last.
 */
static int add_foreign_master(struct port *p, struct ptp_message *m)
{
	struct foreign_clock *fc;
	struct ptp_message *tmp;
	int broke_threshold = 0, diff = 0;

	LIST_FOREACH(fc, &p->foreign_masters, list) {
		if (msg_source_equal(m, fc)) {
			break;
		}
	}
	if (!fc) {
		pr_notice("%s: new foreign master %s", p->log_name,
			pid2str(&m->header.sourcePortIdentity));

		fc = malloc(sizeof(*fc));
		if (!fc) {
			pr_err("low memory, failed to add foreign master");
			return 0;
		}
		memset(fc, 0, sizeof(*fc));
		TAILQ_INIT(&fc->messages);
		LIST_INSERT_HEAD(&p->foreign_masters, fc, list);
		fc->port = p;
		fc->dataset.sender = m->header.sourcePortIdentity;
		/* We do not count this first message, see 9.5.3(b) */
		return 0;
	}

	/*
	 * If this message breaks the threshold, that is an important change.
	 */
	fc_prune(fc);
	if (FOREIGN_MASTER_THRESHOLD - 1 == fc->n_messages) {
		broke_threshold = 1;
	}

	/*
	 * Okay, go ahead and add this announcement.
	 */
	msg_get(m);
	fc->n_messages++;
	TAILQ_INSERT_HEAD(&fc->messages, m, list);

	/*
	 * Test if this announcement contains changed information.
	 */
	if (fc->n_messages > 1) {
		tmp = TAILQ_NEXT(m, list);
		diff = announce_compare(m, tmp);
	}

	return broke_threshold || diff;
}

static int follow_up_info_append(struct ptp_message *m)
{
	struct follow_up_info_tlv *fui;
	struct tlv_extra *extra;

	extra = msg_tlv_append(m, sizeof(*fui));
	if (!extra) {
		return -1;
	}
	fui = (struct follow_up_info_tlv *) extra->tlv;
	fui->type = TLV_ORGANIZATION_EXTENSION;
	fui->length = sizeof(*fui) - sizeof(fui->type) - sizeof(fui->length);
	memcpy(fui->id, ieee8021_id, sizeof(ieee8021_id));
	fui->subtype[2] = 1;

	return 0;
}

static int net_sync_resp_append(struct port *p, struct ptp_message *m)
{
	struct timePropertiesDS tp = clock_time_properties(p->clock);
	struct ClockIdentity cid = clock_identity(p->clock), pid;
	struct currentDS *cds = clock_current_dataset(p->clock);
	struct parent_ds *dad = clock_parent_ds(p->clock);
	struct port *best = clock_best_port(p->clock);
	struct nsm_resp_tlv_head *head;
	struct Timestamp last_sync;
	struct PortAddress *paddr;
	struct ptp_message *tmp;
	struct tlv_extra *extra;
	unsigned char *ptr;
	int tlv_len;

	uint8_t buf[sizeof(*paddr) + sizeof(struct sockaddr_storage)];

	last_sync = tmv_to_Timestamp(clock_ingress_time(p->clock));
	pid = dad->pds.parentPortIdentity.clockIdentity;
	paddr = (struct PortAddress *)buf;

	if (best && !cid_eq(&cid, &pid)) {
		/* Extract the parent's protocol address. */
		paddr->networkProtocol = transport_type(best->trp);
		paddr->addressLength =
			transport_protocol_addr(best->trp, paddr->address);
		if (best->best) {
			tmp = TAILQ_FIRST(&best->best->messages);
			extract_address(tmp, paddr);
		}
	} else {
		/* We are our own parent. */
		paddr->networkProtocol = transport_type(p->trp);
		paddr->addressLength =
			transport_protocol_addr(p->trp, paddr->address);
	}

	tlv_len = sizeof(*head) + sizeof(*extra->foot) + paddr->addressLength;

	extra = msg_tlv_append(m, tlv_len);
	if (!extra) {
		return -1;
	}

	head = (struct nsm_resp_tlv_head *) extra->tlv;
	head->type = TLV_PTPMON_RESP;
	head->length = tlv_len - sizeof(head->type) - sizeof(head->length);
	head->port_state = p->state == PS_GRAND_MASTER ? PS_MASTER : p->state;
	head->parent_addr.networkProtocol = paddr->networkProtocol;
	head->parent_addr.addressLength = paddr->addressLength;
	memcpy(head->parent_addr.address, paddr->address, paddr->addressLength);

	ptr = (unsigned char *) head;
	ptr += sizeof(*head) + paddr->addressLength;
	extra->foot = (struct nsm_resp_tlv_foot *) ptr;

	memcpy(&extra->foot->parent, &dad->pds, sizeof(extra->foot->parent));
	memcpy(&extra->foot->current, cds, sizeof(extra->foot->current));
	memcpy(&extra->foot->timeprop, &tp, sizeof(extra->foot->timeprop));
	memcpy(&extra->foot->lastsync, &last_sync, sizeof(extra->foot->lastsync));

	return 0;
}

static struct follow_up_info_tlv *follow_up_info_extract(struct ptp_message *m)
{
	struct follow_up_info_tlv *f;
	struct tlv_extra *extra;

	TAILQ_FOREACH(extra, &m->tlv_list, list) {
		f = (struct follow_up_info_tlv *) extra->tlv;
		if (f->type == TLV_ORGANIZATION_EXTENSION &&
		    f->length == sizeof(*f) - sizeof(f->type) - sizeof(f->length) &&
//		    memcmp(f->id, ieee8021_id, sizeof(ieee8021_id)) &&
		    !f->subtype[0] && !f->subtype[1] && f->subtype[2] == 1) {
			return f;
		}
	}
	return NULL;
}

static void free_foreign_masters(struct port *p)
{
	struct foreign_clock *fc;
	while ((fc = LIST_FIRST(&p->foreign_masters)) != NULL) {
		LIST_REMOVE(fc, list);
		fc_clear(fc);
		free(fc);
	}
}

static int fup_sync_ok(struct ptp_message *fup, struct ptp_message *sync)
{
	/*
	 * NB - If the sk_check_fupsync option is not enabled, then
	 * both of these time stamps will be zero.
	 */
	if (tmv_cmp(fup->hwts.sw, sync->hwts.sw) < 0) {
		return 0;
	}
	return 1;
}

static int incapable_ignore(struct port *p, struct ptp_message *m)
{
	if (port_capable(p)) {
		return 0;
	}
	if (msg_type(m) == ANNOUNCE || msg_type(m) == SYNC) {
		return 1;
	}
	return 0;
}

static int path_trace_append(struct port *p, struct ptp_message *m,
			     struct parent_ds *dad)
{
	int length = 1 + dad->path_length, ptt_len, tlv_len;
	struct path_trace_tlv *ptt;
	struct tlv_extra *extra;

	if (length > PATH_TRACE_MAX) {
		return -1;
	}

	ptt_len = length * sizeof(struct ClockIdentity);
	tlv_len = ptt_len + sizeof(ptt->type) + sizeof(ptt->length);

	extra = msg_tlv_append(m, tlv_len);
	if (!extra) {
		return -1;
	}
	ptt = (struct path_trace_tlv *) extra->tlv;
	ptt->type = TLV_PATH_TRACE;
	ptt->length = ptt_len;
	memcpy(ptt->cid, dad->ptl, ptt->length);
	ptt->cid[length - 1] = clock_identity(p->clock);

	return 0;
}

static int path_trace_ignore(struct port *p, struct ptp_message *m)
{
	struct path_trace_tlv *ptt;
	struct ClockIdentity cid;
	struct tlv_extra *extra;
	int i, cnt;

	if (!p->path_trace_enabled) {
		return 0;
	}
	if (msg_type(m) != ANNOUNCE) {
		return 0;
	}
	TAILQ_FOREACH(extra, &m->tlv_list, list) {
		ptt = (struct path_trace_tlv *) extra->tlv;
		if (ptt->type != TLV_PATH_TRACE) {
			continue;
		}
		cnt = path_length(ptt);
		cid = clock_identity(p->clock);
		for (i = 0; i < cnt; i++) {
			if (cid_eq(&ptt->cid[i], &cid)) {
				return 1;
			}
		}
	}
	return 0;
}

static void port_stats_inc_rx(struct port *p, const struct ptp_message *msg)
{
	p->stats.rxMsgType[msg_type(msg)]++;
}

static void port_stats_inc_tx(struct port *p, const struct ptp_message *msg)
{
	p->stats.txMsgType[msg_type(msg)]++;
}

static int peer_prepare_and_send(struct port *p, struct ptp_message *msg,
				 enum transport_event event)
{
	int cnt;
	if (msg_pre_send(msg)) {
		return -1;
	}
	if (msg_unicast(msg)) {
		cnt = transport_sendto(p->trp, &p->fda, event, msg);
	} else {
		cnt = transport_peer(p->trp, &p->fda, event, msg);
	}
	if (cnt <= 0) {
		return -1;
	}
	port_stats_inc_tx(p, msg);
	if (msg_sots_valid(msg)) {
		ts_add(&msg->hwts.ts, p->tx_timestamp_offset);
	}
	return 0;
}

int port_capable(struct port *p)
{
	if (!port_is_ieee8021as(p)) {
		/* Normal 1588 ports are always capable. */
		goto capable;
	}

	if (tmv_to_nanoseconds(p->peer_delay) >	p->neighborPropDelayThresh) {
		if (p->asCapable)
			pr_debug("%s: peer_delay (%" PRId64 ") > neighborPropDelayThresh "
				"(%" PRId32 "), resetting asCapable", p->log_name,
				tmv_to_nanoseconds(p->peer_delay),
				p->neighborPropDelayThresh);
		goto not_capable;
	}

	if (tmv_to_nanoseconds(p->peer_delay) <	p->min_neighbor_prop_delay) {
		if (p->asCapable)
			pr_debug("%s: peer_delay (%" PRId64 ") < min_neighbor_prop_delay "
				"(%" PRId32 "), resetting asCapable", p->log_name,
				tmv_to_nanoseconds(p->peer_delay),
				p->min_neighbor_prop_delay);
		goto not_capable;
	}

	if (p->pdr_missing > ALLOWED_LOST_RESPONSES) {
		if (p->asCapable)
			pr_debug("%s: missed %d peer delay resp, "
				"resetting asCapable", p->log_name, p->pdr_missing);
		goto not_capable;
	}

	if (p->multiple_seq_pdr_count) {
		if (p->asCapable)
			pr_debug("%s: multiple sequential peer delay resp, "
				"resetting asCapable", p->log_name);
		goto not_capable;
	}

	if (!p->peer_portid_valid) {
		if (p->asCapable)
			pr_debug("%s: invalid peer port id, "
				"resetting asCapable", p->log_name);
		goto not_capable;
	}

	if (!p->nrate.ratio_valid) {
		if (p->asCapable)
			pr_debug("%s: invalid nrate, "
				"resetting asCapable", p->log_name);
		goto not_capable;
	}

capable:
	if (p->asCapable == NOT_CAPABLE) {
		pr_debug("%s: setting asCapable", p->log_name);
		p->asCapable = AS_CAPABLE;
	}
	return 1;

not_capable:
	if (p->asCapable)
		port_nrate_initialize(p);
	p->asCapable = NOT_CAPABLE;
	return 0;
}

int port_clr_tmo(int fd)
{
	struct itimerspec tmo = {
		{0, 0}, {0, 0}
	};
	return timerfd_settime(fd, 0, &tmo, NULL);
}

static int port_ignore(struct port *p, struct ptp_message *m)
{
	struct ClockIdentity c1, c2;

	if (port_is_uds(p) && msg_type(m) != MANAGEMENT) {
		return 1;
	}
	if (incapable_ignore(p, m)) {
		return 1;
	}
	if (path_trace_ignore(p, m)) {
		return 1;
	}
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

static int port_nsm_reply(struct port *p, struct ptp_message *m)
{
	struct tlv_extra *extra;

	if (!p->net_sync_monitor) {
		return 0;
	}
	if (!p->hybrid_e2e) {
		return 0;
	}
	if (!msg_unicast(m)) {
		return 0;
	}
	TAILQ_FOREACH(extra, &m->tlv_list, list) {
		if (extra->tlv->type == TLV_PTPMON_REQ) {
			return 1;
		}
	}
	return 0;
}

/*
 * Test whether a 802.1AS port may transmit a sync message.
 */
static int port_sync_incapable(struct port *p)
{
	struct ClockIdentity cid;
	struct PortIdentity pid;

	if (!port_is_ieee8021as(p)) {
		return 0;
	}
	if (clock_gm_capable(p->clock)) {
		return 0;
	}
	cid = clock_identity(p->clock);
	pid = clock_parent_identity(p->clock);
	if (cid_eq(&cid, &pid.clockIdentity)) {
		/*
		 * We are the GM, but without gmCapable set.
		 */
		return 1;
	}
	return 0;
}

static int port_is_ieee8021as(struct port *p)
{
	if (p->asCapable == ALWAYS_CAPABLE) {
		return 0;
	}
	return p->follow_up_info ? 1 : 0;
}

static int port_is_uds(struct port *p)
{
	return transport_type(p->trp) == TRANS_UDS;
}

static void port_management_send_error(struct port *p, struct port *ingress,
				       struct ptp_message *msg, int error_id)
{
	if (port_management_error(p->portIdentity, ingress, msg, error_id))
		pr_err("%s: management error failed", p->log_name);
}

static const Octet profile_id_drr[] = {0x00, 0x1B, 0x19, 0x00, 0x01, 0x00};
static const Octet profile_id_p2p[] = {0x00, 0x1B, 0x19, 0x00, 0x02, 0x00};

static int port_management_fill_response(struct port *target,
					 struct ptp_message *rsp, int id)
{
	struct mgmt_clock_description *cd;
	struct management_tlv_datum *mtd;
	struct clock_description *desc;
	struct port_properties_np *ppn;
	struct port_stats_np *psn;
	struct management_tlv *tlv;
	struct port_ds_np *pdsnp;
	struct tlv_extra *extra;
	const char *ts_label;
	struct portDS *pds;
	uint16_t u16;
	uint8_t *buf;
	int datalen;

	extra = tlv_extra_alloc();
	if (!extra) {
		pr_err("failed to allocate TLV descriptor");
		return 0;
	}
	extra->tlv = (struct TLV *) rsp->management.suffix;

	tlv = (struct management_tlv *) rsp->management.suffix;
	tlv->type = TLV_MANAGEMENT;
	tlv->id = id;

	switch (id) {
	case MID_NULL_MANAGEMENT:
		datalen = 0;
		break;
	case MID_CLOCK_DESCRIPTION:
		cd = &extra->cd;
		buf = tlv->data;
		cd->clockType = (UInteger16 *) buf;
		buf += sizeof(*cd->clockType);
		*cd->clockType = clock_type(target->clock);
		cd->physicalLayerProtocol = (struct PTPText *) buf;
		switch(transport_type(target->trp)) {
		case TRANS_UDP_IPV4:
		case TRANS_UDP_IPV6:
		case TRANS_IEEE_802_3:
			ptp_text_set(cd->physicalLayerProtocol, "IEEE 802.3");
			break;
		default:
			ptp_text_set(cd->physicalLayerProtocol, NULL);
			break;
		}
		buf += sizeof(struct PTPText) + cd->physicalLayerProtocol->length;

		cd->physicalAddress = (struct PhysicalAddress *) buf;
		u16 = transport_physical_addr(target->trp,
                                              cd->physicalAddress->address);
		memcpy(&cd->physicalAddress->length, &u16, 2);
		buf += sizeof(struct PhysicalAddress) + u16;

		cd->protocolAddress = (struct PortAddress *) buf;
		u16 = transport_type(target->trp);
		memcpy(&cd->protocolAddress->networkProtocol, &u16, 2);
		u16 = transport_protocol_addr(target->trp,
                                              cd->protocolAddress->address);
		memcpy(&cd->protocolAddress->addressLength, &u16, 2);
		buf += sizeof(struct PortAddress) + u16;

		desc = clock_description(target->clock);
		cd->manufacturerIdentity = buf;
		memcpy(cd->manufacturerIdentity,
                       desc->manufacturerIdentity, OUI_LEN);
		buf += OUI_LEN;
		*(buf++) = 0; /* reserved */

		cd->productDescription = (struct PTPText *) buf;
		ptp_text_copy(cd->productDescription, &desc->productDescription);
		buf += sizeof(struct PTPText) + cd->productDescription->length;

		cd->revisionData = (struct PTPText *) buf;
		ptp_text_copy(cd->revisionData, &desc->revisionData);
		buf += sizeof(struct PTPText) + cd->revisionData->length;

		cd->userDescription = (struct PTPText *) buf;
		ptp_text_copy(cd->userDescription, &desc->userDescription);
		buf += sizeof(struct PTPText) + cd->userDescription->length;

		if (target->delayMechanism == DM_P2P) {
			memcpy(buf, profile_id_p2p, PROFILE_ID_LEN);
		} else {
			memcpy(buf, profile_id_drr, PROFILE_ID_LEN);
		}
		buf += PROFILE_ID_LEN;
		datalen = buf - tlv->data;
		break;
	case MID_PORT_DATA_SET:
		pds = (struct portDS *) tlv->data;
		pds->portIdentity            = target->portIdentity;
		if (target->state == PS_GRAND_MASTER) {
			pds->portState = PS_MASTER;
		} else {
			pds->portState = target->state;
		}
		pds->logMinDelayReqInterval  = target->logMinDelayReqInterval;
		pds->peerMeanPathDelay       = target->peerMeanPathDelay;
		pds->logAnnounceInterval     = target->logAnnounceInterval;
		pds->announceReceiptTimeout  = target->announceReceiptTimeout;
		pds->logSyncInterval         = target->logSyncInterval;
		if (target->delayMechanism) {
			pds->delayMechanism = target->delayMechanism;
		} else {
			pds->delayMechanism = DM_E2E;
		}
		pds->logMinPdelayReqInterval = target->logMinPdelayReqInterval;
		pds->versionNumber           = target->versionNumber;
		datalen = sizeof(*pds);
		break;
	case MID_LOG_ANNOUNCE_INTERVAL:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->logAnnounceInterval;
		datalen = sizeof(*mtd);
		break;
	case MID_ANNOUNCE_RECEIPT_TIMEOUT:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->announceReceiptTimeout;
		datalen = sizeof(*mtd);
		break;
	case MID_LOG_SYNC_INTERVAL:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->logSyncInterval;
		datalen = sizeof(*mtd);
		break;
	case MID_VERSION_NUMBER:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->versionNumber;
		datalen = sizeof(*mtd);
		break;
	case MID_MASTER_ONLY:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->master_only;
		datalen = sizeof(*mtd);
		break;
	case MID_DELAY_MECHANISM:
		mtd = (struct management_tlv_datum *) tlv->data;
		if (target->delayMechanism)
			mtd->val = target->delayMechanism;
		else
			mtd->val = DM_E2E;
		datalen = sizeof(*mtd);
		break;
	case MID_LOG_MIN_PDELAY_REQ_INTERVAL:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->logMinPdelayReqInterval;
		datalen = sizeof(*mtd);
		break;
	case MID_PORT_DATA_SET_NP:
		pdsnp = (struct port_ds_np *) tlv->data;
		pdsnp->neighborPropDelayThresh = target->neighborPropDelayThresh;
		pdsnp->asCapable = target->asCapable;
		datalen = sizeof(*pdsnp);
		break;
	case MID_PORT_PROPERTIES_NP:
		ppn = (struct port_properties_np *)tlv->data;
		ppn->portIdentity = target->portIdentity;
		if (target->state == PS_GRAND_MASTER)
			ppn->port_state = PS_MASTER;
		else
			ppn->port_state = target->state;
		ppn->timestamping = target->timestamping;
		ts_label = interface_label(target->iface);
		ptp_text_set(&ppn->interface, ts_label);
		datalen = sizeof(*ppn) + ppn->interface.length;
		break;
	case MID_PORT_STATS_NP:
		psn = (struct port_stats_np *)tlv->data;
		psn->portIdentity = target->portIdentity;
		psn->stats = target->stats;
		datalen = sizeof(*psn);
		break;
	default:
		/* The caller should *not* respond to this message. */
		tlv_extra_recycle(extra);
		return 0;
	}

	if (datalen % 2) {
		tlv->data[datalen] = 0;
		datalen++;
	}
	tlv->length = sizeof(tlv->id) + datalen;
	rsp->header.messageLength += sizeof(*tlv) + datalen;
	msg_tlv_attach(rsp, extra);

	/* The caller can respond to this message. */
	return 1;
}

static int port_management_get_response(struct port *target,
					struct port *ingress, int id,
					struct ptp_message *req)
{
	struct PortIdentity pid = port_identity(target);
	struct ptp_message *rsp;
	int respond;

	rsp = port_management_reply(pid, ingress, req);
	if (!rsp) {
		return 0;
	}
	respond = port_management_fill_response(target, rsp, id);
	if (respond)
		port_prepare_and_send(ingress, rsp, TRANS_GENERAL);
	msg_put(rsp);
	return respond;
}

static int port_management_set(struct port *target,
			       struct port *ingress, int id,
			       struct ptp_message *req)
{
	int respond = 0;
	struct management_tlv *tlv;
	struct port_ds_np *pdsnp;

	tlv = (struct management_tlv *) req->management.suffix;

	switch (id) {
	case MID_PORT_DATA_SET_NP:
		pdsnp = (struct port_ds_np *) tlv->data;
		target->neighborPropDelayThresh = pdsnp->neighborPropDelayThresh;
		respond = 1;
		break;
	}
	if (respond && !port_management_get_response(target, ingress, id, req))
		pr_err("%s: failed to send management set response", target->log_name);
	return respond ? 1 : 0;
}

static void port_nrate_calculate(struct port *p, tmv_t origin, tmv_t ingress)
{
	struct nrate_estimator *n = &p->nrate;

	/*
	 * We experienced a successful exchanges of peer delay request
	 * and response, reset pdr_missing for this port.
	 */
	p->pdr_missing = 0;

	if (tmv_is_zero(n->ingress1)) {
		n->ingress1 = ingress;
		n->origin1 = origin;
		return;
	}
	n->count++;
	if (n->count < n->max_count) {
		return;
	}
	if (tmv_cmp(ingress, n->ingress1) == 0) {
		pr_warning("bad timestamps in nrate calculation");
		return;
	}
	n->ratio =
		tmv_dbl(tmv_sub(origin, n->origin1)) /
		tmv_dbl(tmv_sub(ingress, n->ingress1));
	n->ingress1 = ingress;
	n->origin1 = origin;
	n->count = 0;
	n->ratio_valid = 1;
}

static void port_nrate_initialize(struct port *p)
{
	int shift = p->freq_est_interval - p->logPdelayReqInterval;

	if (shift < 0)
		shift = 0;
	else if (shift >= sizeof(int) * 8) {
		shift = sizeof(int) * 8 - 1;
		pr_warning("freq_est_interval is too long");
	}

	/* We start in the 'incapable' state. */
	p->pdr_missing = ALLOWED_LOST_RESPONSES + 1;

	p->peer_portid_valid = 0;

	p->nrate.origin1 = tmv_zero();
	p->nrate.ingress1 = tmv_zero();
	p->nrate.max_count = (1U << shift);
	p->nrate.count = 0;
	p->nrate.ratio = 1.0;
	p->nrate.ratio_valid = 0;
}

int port_set_announce_tmo(struct port *p)
{
	return set_tmo_random(p->fda.fd[FD_ANNOUNCE_TIMER],
			      p->announceReceiptTimeout,
			      p->announce_span, p->logAnnounceInterval);
}

int port_set_delay_tmo(struct port *p)
{
	if (p->inhibit_delay_req) {
		return 0;
	}

	if (p->delayMechanism == DM_P2P) {
		return set_tmo_log(p->fda.fd[FD_DELAY_TIMER], 1,
			       p->logPdelayReqInterval);
	} else {
		return set_tmo_random(p->fda.fd[FD_DELAY_TIMER], 0, 2,
				p->logMinDelayReqInterval);
	}
}

static int port_set_manno_tmo(struct port *p)
{
	return set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, p->logAnnounceInterval);
}

int port_set_qualification_tmo(struct port *p)
{
	return set_tmo_log(p->fda.fd[FD_QUALIFICATION_TIMER],
		       1+clock_steps_removed(p->clock), p->logAnnounceInterval);
}

static int port_set_sync_rx_tmo(struct port *p)
{
	return set_tmo_log(p->fda.fd[FD_SYNC_RX_TIMER],
			   p->syncReceiptTimeout, p->logSyncInterval);
}

static int port_set_sync_tx_tmo(struct port *p)
{
	return set_tmo_log(p->fda.fd[FD_SYNC_TX_TIMER], 1, p->logSyncInterval);
}

void port_show_transition(struct port *p, enum port_state next,
			  enum fsm_event event)
{
	if (event == EV_FAULT_DETECTED) {
		pr_notice("%s: %s to %s on %s (%s)", p->log_name,
			  ps_str[p->state], ps_str[next], ev_str[event],
			  ft_str(last_fault_type(p)));
	} else {
		pr_notice("%s: %s to %s on %s", p->log_name,
			  ps_str[p->state], ps_str[next], ev_str[event]);
	}
}

static void port_slave_priority_warning(struct port *p)
{
	const char *n = p->log_name;
	pr_warning("%s: master state recommended in slave only mode", n);
	pr_warning("%s: defaultDS.priority1 probably misconfigured", n);
}

static void message_interval_request(struct port *p,
				     enum servo_state last_state,
				     Integer8 sync_interval)
{
	if (!p->msg_interval_request)
		return;

	if (last_state == SERVO_LOCKED) {
		p->logPdelayReqInterval = p->operLogPdelayReqInterval;
		p->logSyncInterval = p->operLogSyncInterval;
		port_tx_interval_request(p, SIGNAL_NO_CHANGE,
					 p->logSyncInterval,
					 SIGNAL_NO_CHANGE);
		port_dispatch(p, EV_MASTER_CLOCK_SELECTED, 0);
	} else if (sync_interval != p->operLogSyncInterval) {
		/*
		 * The most likely reason for this to happen is the
		 * master daemon re-initialized due to some fault.
		 */
		servo_reset(clock_servo(p->clock));
		port_dispatch(p, EV_SYNCHRONIZATION_FAULT, 0);
	}
}

static void port_synchronize(struct port *p,
			     uint16_t seqid,
			     tmv_t ingress_ts,
			     struct timestamp origin_ts,
			     Integer64 correction1, Integer64 correction2,
			     Integer8 sync_interval)
{
	enum servo_state state, last_state;
	tmv_t t1, t1c, t2, c1, c2;

	port_set_sync_rx_tmo(p);

	t1 = timestamp_to_tmv(origin_ts);
	t2 = ingress_ts;
	c1 = correction_to_tmv(correction1);
	c2 = correction_to_tmv(correction2);
	t1c = tmv_add(t1, tmv_add(c1, c2));

	switch (p->state) {
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		monitor_sync(p->slave_event_monitor,
			     clock_parent_identity(p->clock), seqid,
			     t1, tmv_add(c1, c2), t2);
		break;
	default:
		break;
	}

	last_state = clock_servo_state(p->clock);
	state = clock_synchronize(p->clock, t2, t1c);
	switch (state) {
	case SERVO_UNLOCKED:
		port_dispatch(p, EV_SYNCHRONIZATION_FAULT, 0);
		if (servo_offset_threshold(clock_servo(p->clock)) != 0 &&
		    sync_interval != p->initialLogSyncInterval) {
			p->logPdelayReqInterval = p->logMinPdelayReqInterval;
			p->logSyncInterval = p->initialLogSyncInterval;
			port_tx_interval_request(p, SIGNAL_NO_CHANGE,
						 SIGNAL_SET_INITIAL,
						 SIGNAL_NO_CHANGE);
		}
		break;
	case SERVO_JUMP:
		port_dispatch(p, EV_SYNCHRONIZATION_FAULT, 0);
		flush_delay_req(p);
		if (p->peer_delay_req) {
			msg_put(p->peer_delay_req);
			p->peer_delay_req = NULL;
		}
		break;
	case SERVO_LOCKED:
		port_dispatch(p, EV_MASTER_CLOCK_SELECTED, 0);
		break;
	case SERVO_LOCKED_STABLE:
		message_interval_request(p, last_state, sync_interval);
		port_dispatch(p, EV_MASTER_CLOCK_SELECTED, 0);
		break;
	}
}

static void port_syfufsm_print_mismatch(struct port *p, enum syfu_event event,
					struct ptp_message *m)
{
	int expected_msgtype;

	if (event == SYNC_MISMATCH)
		expected_msgtype = FOLLOW_UP;
	else
		expected_msgtype = SYNC;

	pr_debug("%s: have %s %hu, expecting %s but got %s %hu, dropping",
		 p->log_name, msg_type_string(msg_type(p->last_syncfup)),
		 p->last_syncfup->header.sequenceId,
		 msg_type_string(expected_msgtype),
		 msg_type_string(msg_type(m)), m->header.sequenceId);
}

/*
 * Handle out of order packets. The network stack might
 * provide the follow up _before_ the sync message. After all,
 * they can arrive on two different ports. In addition, time
 * stamping in PHY devices might delay the event packets.
 */
static void port_syfufsm(struct port *p, enum syfu_event event,
			 struct ptp_message *m)
{
	struct ptp_message *syn, *fup;

	switch (p->syfu) {
	case SF_EMPTY:
		switch (event) {
		case SYNC_MISMATCH:
			msg_get(m);
			p->last_syncfup = m;
			p->syfu = SF_HAVE_SYNC;
			break;
		case FUP_MISMATCH:
			msg_get(m);
			p->last_syncfup = m;
			p->syfu = SF_HAVE_FUP;
			break;
		case SYNC_MATCH:
			break;
		case FUP_MATCH:
			break;
		}
		break;

	case SF_HAVE_SYNC:
		switch (event) {
		case SYNC_MISMATCH:
			port_syfufsm_print_mismatch(p, event, m);
			msg_put(p->last_syncfup);
			msg_get(m);
			p->last_syncfup = m;
			break;
		case SYNC_MATCH:
			break;
		case FUP_MISMATCH:
			port_syfufsm_print_mismatch(p, event, m);
			msg_put(p->last_syncfup);
			msg_get(m);
			p->last_syncfup = m;
			p->syfu = SF_HAVE_FUP;
			break;
		case FUP_MATCH:
			syn = p->last_syncfup;
			port_synchronize(p, syn->header.sequenceId,
					 syn->hwts.ts, m->ts.pdu,
					 syn->header.correction,
					 m->header.correction,
					 m->header.logMessageInterval);
			msg_put(p->last_syncfup);
			p->syfu = SF_EMPTY;
			break;
		}
		break;

	case SF_HAVE_FUP:
		switch (event) {
		case SYNC_MISMATCH:
			port_syfufsm_print_mismatch(p, event, m);
			msg_put(p->last_syncfup);
			msg_get(m);
			p->last_syncfup = m;
			p->syfu = SF_HAVE_SYNC;
			break;
		case SYNC_MATCH:
			fup = p->last_syncfup;
			port_synchronize(p, fup->header.sequenceId,
					 m->hwts.ts, fup->ts.pdu,
					 m->header.correction,
					 fup->header.correction,
					 m->header.logMessageInterval);
			msg_put(p->last_syncfup);
			p->syfu = SF_EMPTY;
			break;
		case FUP_MISMATCH:
			port_syfufsm_print_mismatch(p, event, m);
			msg_put(p->last_syncfup);
			msg_get(m);
			p->last_syncfup = m;
			break;
		case FUP_MATCH:
			break;
		}
		break;
	}
}

static int port_pdelay_request(struct port *p)
{
	struct ptp_message *msg;
	int err;

	/* If multiple pdelay resp were not detected the counter can be reset */
	if (!p->multiple_pdr_detected) {
		p->multiple_seq_pdr_count = 0;
	}
	p->multiple_pdr_detected = 0;

	msg = msg_allocate();
	if (!msg) {
		return -1;
	}

	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = PDELAY_REQ | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct pdelay_req_msg);
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.correction         = -p->asymmetry;
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.delayreq++;
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = port_is_ieee8021as(p) ?
		p->logPdelayReqInterval : 0x7f;

	if (unicast_client_enabled(p) && p->unicast_master_table->peer_name) {
		msg->address = p->unicast_master_table->peer_addr.address;
		msg->header.flagField[0] |= UNICAST;
	}

	err = peer_prepare_and_send(p, msg, TRANS_EVENT);
	if (err) {
		pr_err("%s: send peer delay request failed", p->log_name);
		goto out;
	}
	if (msg_sots_missing(msg)) {
		pr_err("missing timestamp on transmitted peer delay request");
		goto out;
	}

	if (p->peer_delay_req) {
		if (port_capable(p)) {
			p->pdr_missing++;
		}
		msg_put(p->peer_delay_req);
	}
	p->peer_delay_req = msg;
	return 0;
out:
	msg_put(msg);
	return -1;
}

int port_delay_request(struct port *p)
{
	struct ptp_message *msg;

	/* Time to send a new request, forget current pdelay resp and fup */
	if (p->peer_delay_resp) {
		msg_put(p->peer_delay_resp);
		p->peer_delay_resp = NULL;
	}
	if (p->peer_delay_fup) {
		msg_put(p->peer_delay_fup);
		p->peer_delay_fup = NULL;
	}

	if (p->delayMechanism == DM_P2P) {
		return port_pdelay_request(p);
	}

	msg = msg_allocate();
	if (!msg) {
		return -1;
	}

	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = DELAY_REQ | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct delay_req_msg);
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.correction         = -p->asymmetry;
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.delayreq++;
	msg->header.control            = CTL_DELAY_REQ;
	msg->header.logMessageInterval = 0x7f;

	if (p->hybrid_e2e) {
		struct ptp_message *dst = TAILQ_FIRST(&p->best->messages);
		msg->address = dst->address;
		msg->header.flagField[0] |= UNICAST;
	}

	if (port_prepare_and_send(p, msg, TRANS_EVENT)) {
		pr_err("%s: send delay request failed", p->log_name);
		goto out;
	}
	if (msg_sots_missing(msg)) {
		pr_err("missing timestamp on transmitted delay request");
		goto out;
	}

	TAILQ_INSERT_HEAD(&p->delay_req, msg, list);

	return 0;
out:
	msg_put(msg);
	return -1;
}

int port_tx_announce(struct port *p, struct address *dst)
{
	struct timePropertiesDS tp = clock_time_properties(p->clock);
	struct parent_ds *dad = clock_parent_ds(p->clock);
	struct ptp_message *msg;
	int err;

	if (p->inhibit_multicast_service && !dst) {
		return 0;
	}
	if (!port_capable(p)) {
		return 0;
	}
	msg = msg_allocate();
	if (!msg) {
		return -1;
	}

	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = ANNOUNCE | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct announce_msg);
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.announce++;
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = p->logAnnounceInterval;

	msg->header.flagField[1] = tp.flags;

	if (dst) {
		msg->address = *dst;
		msg->header.flagField[0] |= UNICAST;
	}
	msg->announce.currentUtcOffset        = tp.currentUtcOffset;
	msg->announce.grandmasterPriority1    = dad->pds.grandmasterPriority1;
	msg->announce.grandmasterClockQuality = dad->pds.grandmasterClockQuality;
	msg->announce.grandmasterPriority2    = dad->pds.grandmasterPriority2;
	msg->announce.grandmasterIdentity     = dad->pds.grandmasterIdentity;
	msg->announce.stepsRemoved            = clock_steps_removed(p->clock);
	msg->announce.timeSource              = tp.timeSource;

	if (p->path_trace_enabled && path_trace_append(p, msg, dad)) {
		pr_err("%s: append path trace failed", p->log_name);
	}

	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: send announce failed", p->log_name);
	}
	msg_put(msg);
	return err;
}

int port_tx_sync(struct port *p, struct address *dst)
{
	struct ptp_message *msg, *fup;
	int err, event;

	switch (p->timestamping) {
	case TS_SOFTWARE:
	case TS_LEGACY_HW:
	case TS_HARDWARE:
		event = TRANS_EVENT;
		break;
	case TS_ONESTEP:
		event = TRANS_ONESTEP;
		break;
	case TS_P2P1STEP:
		event = TRANS_P2P1STEP;
		break;
	default:
		return -1;
	}

	if (p->inhibit_multicast_service && !dst) {
		return 0;
	}
	if (!port_capable(p)) {
		return 0;
	}
	if (port_sync_incapable(p)) {
		return 0;
	}
	msg = msg_allocate();
	if (!msg) {
		return -1;
	}
	fup = msg_allocate();
	if (!fup) {
		msg_put(msg);
		return -1;
	}

	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = SYNC | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct sync_msg);
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.sync++;
	msg->header.control            = CTL_SYNC;
	msg->header.logMessageInterval = p->logSyncInterval;

	if (p->timestamping != TS_ONESTEP && p->timestamping != TS_P2P1STEP) {
		msg->header.flagField[0] |= TWO_STEP;
	}

	if (dst) {
		msg->address = *dst;
		msg->header.flagField[0] |= UNICAST;
		msg->header.logMessageInterval = 0x7f;
	}
	err = port_prepare_and_send(p, msg, event);
	if (err) {
		pr_err("%s: send sync failed", p->log_name);
		goto out;
	}
	if (p->timestamping == TS_ONESTEP || p->timestamping == TS_P2P1STEP) {
		goto out;
	} else if (msg_sots_missing(msg)) {
		pr_err("missing timestamp on transmitted sync");
		err = -1;
		goto out;
	}

	/*
	 * Send the follow up message right away.
	 */
	fup->hwts.type = p->timestamping;

	fup->header.tsmt               = FOLLOW_UP | p->transportSpecific;
	fup->header.ver                = PTP_VERSION;
	fup->header.messageLength      = sizeof(struct follow_up_msg);
	fup->header.domainNumber       = clock_domain_number(p->clock);
	fup->header.sourcePortIdentity = p->portIdentity;
	fup->header.sequenceId         = p->seqnum.sync - 1;
	fup->header.control            = CTL_FOLLOW_UP;
	fup->header.logMessageInterval = p->logSyncInterval;

	fup->follow_up.preciseOriginTimestamp = tmv_to_Timestamp(msg->hwts.ts);

	if (dst) {
		fup->address = *dst;
		fup->header.flagField[0] |= UNICAST;
	}
	if (p->follow_up_info && follow_up_info_append(fup)) {
		pr_err("%s: append fup info failed", p->log_name);
		err = -1;
		goto out;
	}

	err = port_prepare_and_send(p, fup, TRANS_GENERAL);
	if (err) {
		pr_err("%s: send follow up failed", p->log_name);
	}
out:
	msg_put(msg);
	msg_put(fup);
	return err;
}

/*
 * port initialize and disable
 */
int port_is_enabled(struct port *p)
{
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
	return 1;
}

void flush_last_sync(struct port *p)
{
	if (p->syfu != SF_EMPTY) {
		msg_put(p->last_syncfup);
		p->syfu = SF_EMPTY;
	}
}

void flush_delay_req(struct port *p)
{
	struct ptp_message *m;
	while ((m = TAILQ_FIRST(&p->delay_req)) != NULL) {
		TAILQ_REMOVE(&p->delay_req, m, list);
		msg_put(m);
	}
}

static void flush_peer_delay(struct port *p)
{
	if (p->peer_delay_req) {
		msg_put(p->peer_delay_req);
		p->peer_delay_req = NULL;
	}
	if (p->peer_delay_resp) {
		msg_put(p->peer_delay_resp);
		p->peer_delay_resp = NULL;
	}
	if (p->peer_delay_fup) {
		msg_put(p->peer_delay_fup);
		p->peer_delay_fup = NULL;
	}
}

static void port_clear_fda(struct port *p, int count)
{
	int i;

	for (i = 0; i < count; i++)
		p->fda.fd[i] = -1;
}

void port_disable(struct port *p)
{
	int i;

	tc_flush(p);
	flush_last_sync(p);
	flush_delay_req(p);
	flush_peer_delay(p);

	p->best = NULL;
	free_foreign_masters(p);
	transport_close(p->trp, &p->fda);

	for (i = 0; i < N_TIMER_FDS; i++) {
		close(p->fda.fd[FD_FIRST_TIMER + i]);
	}

	/* Keep rtnl socket to get link status info. */
	port_clear_fda(p, FD_RTNL);
	clock_fda_changed(p->clock);
}

int port_initialize(struct port *p)
{
	struct config *cfg = clock_config(p->clock);
	int fd[N_TIMER_FDS], i;

	p->multiple_seq_pdr_count  = 0;
	p->multiple_pdr_detected   = 0;
	p->last_fault_type         = FT_UNSPECIFIED;
	p->logMinDelayReqInterval  = config_get_int(cfg, p->name, "logMinDelayReqInterval");
	p->peerMeanPathDelay       = 0;
	p->initialLogAnnounceInterval = config_get_int(cfg, p->name, "logAnnounceInterval");
	p->logAnnounceInterval     = p->initialLogAnnounceInterval;
	p->inhibit_announce        = config_get_int(cfg, p->name, "inhibit_announce");
	p->ignore_source_id        = config_get_int(cfg, p->name, "ignore_source_id");
	p->announceReceiptTimeout  = config_get_int(cfg, p->name, "announceReceiptTimeout");
	p->syncReceiptTimeout      = config_get_int(cfg, p->name, "syncReceiptTimeout");
	p->transportSpecific       = config_get_int(cfg, p->name, "transportSpecific");
	p->transportSpecific     <<= 4;
	p->match_transport_specific = !config_get_int(cfg, p->name, "ignore_transport_specific");
	p->localPriority           = config_get_int(cfg, p->name, "G.8275.portDS.localPriority");
	p->initialLogSyncInterval  = config_get_int(cfg, p->name, "logSyncInterval");
	p->logSyncInterval         = p->initialLogSyncInterval;
	p->operLogSyncInterval     = config_get_int(cfg, p->name, "operLogSyncInterval");
	p->logMinPdelayReqInterval = config_get_int(cfg, p->name, "logMinPdelayReqInterval");
	p->logPdelayReqInterval    = p->logMinPdelayReqInterval;
	p->operLogPdelayReqInterval = config_get_int(cfg, p->name, "operLogPdelayReqInterval");
	p->neighborPropDelayThresh = config_get_int(cfg, p->name, "neighborPropDelayThresh");
	p->min_neighbor_prop_delay = config_get_int(cfg, p->name, "min_neighbor_prop_delay");
	p->delay_response_timeout  = config_get_int(cfg, p->name, "delay_response_timeout");

	if (config_get_int(cfg, p->name, "asCapable") == AS_CAPABLE_TRUE) {
		p->asCapable = ALWAYS_CAPABLE;
	} else {
		p->asCapable = NOT_CAPABLE;
	}

	p->inhibit_delay_req = config_get_int(cfg, p->name, "inhibit_delay_req");
	if (p->inhibit_delay_req && p->asCapable != ALWAYS_CAPABLE) {
		pr_err("inhibit_delay_req can only be set when asCapable == 'true'.");
		return -1;
	}

	for (i = 0; i < N_TIMER_FDS; i++) {
		fd[i] = -1;
	}
	for (i = 0; i < N_TIMER_FDS; i++) {
		fd[i] = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd[i] < 0) {
			pr_err("timerfd_create: %s", strerror(errno));
			goto no_timers;
		}
	}
	if (transport_open(p->trp, p->iface, &p->fda, p->timestamping))
		goto no_tropen;

	for (i = 0; i < N_TIMER_FDS; i++) {
		p->fda.fd[FD_FIRST_TIMER + i] = fd[i];
	}

	if (port_set_announce_tmo(p)) {
		goto no_tmo;
	}
	if (unicast_client_enabled(p) && unicast_client_set_tmo(p)) {
		goto no_tmo;
	}

	/* No need to open rtnl socket on UDS port. */
	if (!port_is_uds(p)) {
		/*
		 * The delay timer is usually started when the device
		 * transitions to PS_LISTENING. But, we are skipping the state
		 * when BMCA == 'noop'. So, start the timer here.
		 */
		if (p->bmca == BMCA_NOOP) {
			port_set_delay_tmo(p);
		}
		if (p->fda.fd[FD_RTNL] == -1) {
			p->fda.fd[FD_RTNL] = rtnl_open();
		}
		if (p->fda.fd[FD_RTNL] >= 0) {
			const char *ifname = interface_name(p->iface);
			rtnl_link_query(p->fda.fd[FD_RTNL], ifname);
		}
	}

	port_nrate_initialize(p);

	clock_fda_changed(p->clock);
	return 0;

no_tmo:
	transport_close(p->trp, &p->fda);
no_tropen:
no_timers:
	for (i = 0; i < N_TIMER_FDS; i++) {
		if (fd[i] >= 0)
			close(fd[i]);
	}
	return -1;
}

static int port_renew_transport(struct port *p)
{
	int res;

	if (!port_is_enabled(p)) {
		return 0;
	}

	/* Closing and binding of raw sockets is too slow and unnecessary */
	if (transport_type(p->trp) == TRANS_IEEE_802_3) {
		return 0;
	}

	transport_close(p->trp, &p->fda);
	port_clear_fda(p, FD_FIRST_TIMER);
	res = transport_open(p->trp, p->iface, &p->fda, p->timestamping);
	/* Need to call clock_fda_changed even if transport_open failed in
	 * order to update clock to the now closed descriptors. */
	clock_fda_changed(p->clock);
	return res;
}

/*
 * Returns non-zero if the announce message is different than last.
 */
static int update_current_master(struct port *p, struct ptp_message *m)
{
	struct foreign_clock *fc = p->best;
	struct ptp_message *tmp;
	struct parent_ds *dad;
	struct path_trace_tlv *ptt;
	struct timePropertiesDS tds;

	if (!msg_source_equal(m, fc))
		return add_foreign_master(p, m);

	if (p->state != PS_PASSIVE) {
		tds.currentUtcOffset = m->announce.currentUtcOffset;
		tds.flags = m->header.flagField[1];
		tds.timeSource = m->announce.timeSource;
		clock_update_time_properties(p->clock, tds);
	}
	if (p->path_trace_enabled) {
		ptt = (struct path_trace_tlv *) m->announce.suffix;
		dad = clock_parent_ds(p->clock);
		memcpy(dad->ptl, ptt->cid, ptt->length);
		dad->path_length = path_length(ptt);
	}
	port_set_announce_tmo(p);
	fc_prune(fc);
	msg_get(m);
	fc->n_messages++;
	TAILQ_INSERT_HEAD(&fc->messages, m, list);
	if (fc->n_messages > 1) {
		tmp = TAILQ_NEXT(m, list);
		return announce_compare(m, tmp);
	}
	return 0;
}

struct dataset *port_best_foreign(struct port *port)
{
	return port->best ? &port->best->dataset : NULL;
}

/* message processing routines */

/*
 * Returns non-zero if the announce message is both qualified and different.
 */
int process_announce(struct port *p, struct ptp_message *m)
{
	int result = 0;

	if (m->announce.stepsRemoved >= clock_max_steps_removed(p->clock)) {
		return result;
	}

	if (m->announce.grandmasterClockQuality.clockClass >
		clock_get_clock_class_threshold(p->clock)) {
		pl_err(60, "%s: Master clock quality received is "
			"greater than configured, ignoring master!",
			p->log_name);
		return result;
	}

	switch (p->state) {
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
		break;
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_MASTER:
	case PS_GRAND_MASTER:
		result = add_foreign_master(p, m);
		break;
	case PS_PASSIVE:
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		result = update_current_master(p, m);
		break;
	}
	return result;
}

static int process_delay_req(struct port *p, struct ptp_message *m)
{
	int err, nsm, saved_seqnum_sync;
	struct ptp_message *msg;

	nsm = port_nsm_reply(p, m);

	if (!nsm && p->state != PS_MASTER && p->state != PS_GRAND_MASTER) {
		return 0;
	}

	if (p->delayMechanism == DM_P2P) {
		pr_warning("%s: delay request on P2P port", p->log_name);
		return 0;
	}

	msg = msg_allocate();
	if (!msg) {
		return -1;
	}

	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = DELAY_RESP | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct delay_resp_msg);
	msg->header.domainNumber       = m->header.domainNumber;
	msg->header.correction         = m->header.correction;
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = m->header.sequenceId;
	msg->header.control            = CTL_DELAY_RESP;
	msg->header.logMessageInterval = p->logMinDelayReqInterval;

	msg->delay_resp.receiveTimestamp = tmv_to_Timestamp(m->hwts.ts);

	msg->delay_resp.requestingPortIdentity = m->header.sourcePortIdentity;

	if (p->hybrid_e2e && msg_unicast(m)) {
		msg->address = m->address;
		msg->header.flagField[0] |= UNICAST;
		msg->header.logMessageInterval = 0x7f;
	}
	if (nsm && net_sync_resp_append(p, msg)) {
		pr_err("%s: append NSM failed", p->log_name);
		err = -1;
		goto out;
	}
	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: send delay response failed", p->log_name);
		goto out;
	}
	if (nsm) {
		saved_seqnum_sync = p->seqnum.sync;
		p->seqnum.sync = m->header.sequenceId;
		err = port_tx_sync(p, &m->address);
		p->seqnum.sync = saved_seqnum_sync;
	}
out:
	msg_put(msg);
	return err;
}

void process_delay_resp(struct port *p, struct ptp_message *m)
{
	struct delay_resp_msg *rsp = &m->delay_resp;
	struct ptp_message *req;
	tmv_t c3, t3, t4, t4c;

	if (p->state != PS_UNCALIBRATED && p->state != PS_SLAVE) {
		return;
	}
	if (!pid_eq(&rsp->requestingPortIdentity, &p->portIdentity)) {
		return;
	}
	if (check_source_identity(p, m)) {
		return;
	}
	TAILQ_FOREACH(req, &p->delay_req, list) {
		if (rsp->hdr.sequenceId == ntohs(req->delay_req.hdr.sequenceId)) {
			break;
		}
	}
	if (!req) {
		return;
	}

	/* Valid Delay Response received, reset the counter */
	p->delay_response_counter = 0;

	c3 = correction_to_tmv(m->header.correction);
	t3 = req->hwts.ts;
	t4 = timestamp_to_tmv(m->ts.pdu);
	t4c = tmv_sub(t4, c3);

	monitor_delay(p->slave_event_monitor, clock_parent_identity(p->clock),
		      m->header.sequenceId, t3, c3, t4);

	clock_path_delay(p->clock, t3, t4c);

	TAILQ_REMOVE(&p->delay_req, req, list);
	msg_put(req);

	if (p->logMinDelayReqInterval == rsp->hdr.logMessageInterval) {
		return;
	}
	if (msg_unicast(m)) {
		/* Unicast responses have logMinDelayReqInterval set to 0x7F. */
		return;
	}
	if (rsp->hdr.logMessageInterval < -10 ||
	    rsp->hdr.logMessageInterval > 22) {
		pl_info(300, "%s: ignore bogus delay request interval 2^%d",
			p->log_name, rsp->hdr.logMessageInterval);
		return;
	}
	p->logMinDelayReqInterval = rsp->hdr.logMessageInterval;
	pr_notice("%s: minimum delay request interval 2^%d",
		  p->log_name, p->logMinDelayReqInterval);
	port_set_delay_tmo(p);
}

void process_follow_up(struct port *p, struct ptp_message *m)
{
	enum syfu_event event;
	switch (p->state) {
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_MASTER:
	case PS_GRAND_MASTER:
	case PS_PASSIVE:
		return;
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		break;
	}

	if (check_source_identity(p, m)) {
		return;
	}

	if (p->follow_up_info) {
		struct follow_up_info_tlv *fui = follow_up_info_extract(m);
		if (!fui)
			return;
		clock_follow_up_info(p->clock, fui);
	}

	if (p->syfu == SF_HAVE_SYNC &&
	    p->last_syncfup->header.sequenceId == m->header.sequenceId) {
		event = FUP_MATCH;
	} else {
		event = FUP_MISMATCH;
	}
	port_syfufsm(p, event, m);
}

int process_pdelay_req(struct port *p, struct ptp_message *m)
{
	struct ptp_message *rsp, *fup;
	enum transport_event event;
	int err;

	switch (p->timestamping) {
	case TS_SOFTWARE:
	case TS_LEGACY_HW:
	case TS_HARDWARE:
	case TS_ONESTEP:
		event = TRANS_EVENT;
		break;
	case TS_P2P1STEP:
		event = TRANS_P2P1STEP;
		break;
	default:
		return -1;
	}

	if (p->delayMechanism == DM_E2E) {
		pr_warning("%s: pdelay_req on E2E port", p->log_name);
		return 0;
	}
	if (p->delayMechanism == DM_AUTO) {
		pr_info("%s: peer detected, switch to P2P", p->log_name);
		p->delayMechanism = DM_P2P;
		port_set_delay_tmo(p);
	}
	if (p->peer_portid_valid) {
		if (!pid_eq(&p->peer_portid, &m->header.sourcePortIdentity)) {
			pr_err("%s: received pdelay_req msg with "
				"unexpected peer port id %s",
				p->log_name,
				pid2str(&m->header.sourcePortIdentity));
			p->peer_portid_valid = 0;
			port_capable(p);
		}
	} else {
		p->peer_portid_valid = 1;
		p->peer_portid = m->header.sourcePortIdentity;
		pr_debug("%s: peer port id set to %s", p->log_name,
			pid2str(&p->peer_portid));
	}

	rsp = msg_allocate();
	if (!rsp) {
		return -1;
	}

	fup = msg_allocate();
	if (!fup) {
		msg_put(rsp);
		return -1;
	}

	rsp->hwts.type = p->timestamping;

	rsp->header.tsmt               = PDELAY_RESP | p->transportSpecific;
	rsp->header.ver                = PTP_VERSION;
	rsp->header.messageLength      = sizeof(struct pdelay_resp_msg);
	rsp->header.domainNumber       = m->header.domainNumber;
	rsp->header.sourcePortIdentity = p->portIdentity;
	rsp->header.sequenceId         = m->header.sequenceId;
	rsp->header.control            = CTL_OTHER;
	rsp->header.logMessageInterval = 0x7f;

	/*
	 * NB - We do not have any fraction nanoseconds for the correction
	 * fields, neither in the response or the follow up.
	 */
	if (p->timestamping == TS_P2P1STEP) {
		rsp->header.correction = m->header.correction;
		rsp->header.correction += p->tx_timestamp_offset;
		rsp->header.correction += p->rx_timestamp_offset;
	} else {
		rsp->header.flagField[0] |= TWO_STEP;
		rsp->pdelay_resp.requestReceiptTimestamp =
			tmv_to_Timestamp(m->hwts.ts);
	}
	rsp->pdelay_resp.requestingPortIdentity = m->header.sourcePortIdentity;

	if (msg_unicast(m)) {
		rsp->address = m->address;
		rsp->header.flagField[0] |= UNICAST;
	}

	err = peer_prepare_and_send(p, rsp, event);
	if (err) {
		pr_err("%s: send peer delay response failed", p->log_name);
		goto out;
	}
	if (p->timestamping == TS_P2P1STEP) {
		goto out;
	} else if (msg_sots_missing(rsp)) {
		pr_err("missing timestamp on transmitted peer delay response");
		err = -1;
		goto out;
	}

	/*
	 * Send the follow up message right away.
	 */
	fup->hwts.type = p->timestamping;

	fup->header.tsmt               = PDELAY_RESP_FOLLOW_UP | p->transportSpecific;
	fup->header.ver                = PTP_VERSION;
	fup->header.messageLength      = sizeof(struct pdelay_resp_fup_msg);
	fup->header.domainNumber       = m->header.domainNumber;
	fup->header.correction         = m->header.correction;
	fup->header.sourcePortIdentity = p->portIdentity;
	fup->header.sequenceId         = m->header.sequenceId;
	fup->header.control            = CTL_OTHER;
	fup->header.logMessageInterval = 0x7f;

	fup->pdelay_resp_fup.requestingPortIdentity = m->header.sourcePortIdentity;

	fup->pdelay_resp_fup.responseOriginTimestamp =
		tmv_to_Timestamp(rsp->hwts.ts);

	if (msg_unicast(m)) {
		fup->address = m->address;
		fup->header.flagField[0] |= UNICAST;
	}

	err = peer_prepare_and_send(p, fup, TRANS_GENERAL);
	if (err) {
		pr_err("%s: send pdelay_resp_fup failed", p->log_name);
	}
out:
	msg_put(rsp);
	msg_put(fup);
	return err;
}

static void port_peer_delay(struct port *p)
{
	tmv_t c1, c2, t1, t2, t3, t3c, t4;
	struct ptp_message *req = p->peer_delay_req;
	struct ptp_message *rsp = p->peer_delay_resp;
	struct ptp_message *fup = p->peer_delay_fup;

	/* Check for response, validate port and sequence number. */

	if (!rsp)
		return;

	if (!pid_eq(&rsp->pdelay_resp.requestingPortIdentity, &p->portIdentity))
		return;

	if (rsp->header.sequenceId != ntohs(req->header.sequenceId))
		return;

	t1 = req->hwts.ts;
	t4 = rsp->hwts.ts;
	c1 = correction_to_tmv(rsp->header.correction + p->asymmetry);

	/* Process one-step response immediately. */
	if (one_step(rsp)) {
		t2 = tmv_zero();
		t3 = tmv_zero();
		c2 = tmv_zero();
		goto calc;
	}

	/* Check for follow up, validate port and sequence number. */

	if (!fup)
		return;

	if (!pid_eq(&fup->pdelay_resp_fup.requestingPortIdentity, &p->portIdentity))
		return;

	if (fup->header.sequenceId != rsp->header.sequenceId)
		return;

	if (!source_pid_eq(fup, rsp))
		return;

	/* Process follow up response. */
	t2 = timestamp_to_tmv(rsp->ts.pdu);
	t3 = timestamp_to_tmv(fup->ts.pdu);
	c2 = correction_to_tmv(fup->header.correction);
calc:
	t3c = tmv_add(t3, tmv_add(c1, c2));

	if (p->follow_up_info)
		port_nrate_calculate(p, t3c, t4);

	tsproc_set_clock_rate_ratio(p->tsproc, p->nrate.ratio *
				    clock_rate_ratio(p->clock));
	tsproc_up_ts(p->tsproc, t1, t2);
	tsproc_down_ts(p->tsproc, t3c, t4);
	if (tsproc_update_delay(p->tsproc, &p->peer_delay))
		return;

	p->peerMeanPathDelay = tmv_to_TimeInterval(p->peer_delay);

	if (p->state == PS_UNCALIBRATED || p->state == PS_SLAVE) {
		clock_peer_delay(p->clock, p->peer_delay, t1, t2,
				 p->nrate.ratio);
	}

	msg_put(p->peer_delay_req);
	p->peer_delay_req = NULL;
}

int process_pdelay_resp(struct port *p, struct ptp_message *m)
{
	if (p->peer_delay_resp) {
		if (!source_pid_eq(p->peer_delay_resp, m)) {
			pr_err("%s: multiple peer responses", p->log_name);
			if (!p->multiple_pdr_detected) {
				p->multiple_pdr_detected = 1;
				p->multiple_seq_pdr_count++;
			}
			if (p->multiple_seq_pdr_count >= 3) {
				p->last_fault_type = FT_BAD_PEER_NETWORK;
				return -1;
			}
		}
	}
	if (!p->peer_delay_req) {
		pr_err("%s: rogue peer delay response", p->log_name);
		return -1;
	}
	if (p->peer_portid_valid) {
		if (!pid_eq(&p->peer_portid, &m->header.sourcePortIdentity)) {
			pr_err("%s: received pdelay_resp msg with "
				"unexpected peer port id %s",
				p->log_name,
				pid2str(&m->header.sourcePortIdentity));
			p->peer_portid_valid = 0;
			port_capable(p);
		}
	} else {
		p->peer_portid_valid = 1;
		p->peer_portid = m->header.sourcePortIdentity;
		pr_debug("%s: peer port id set to %s", p->log_name,
			pid2str(&p->peer_portid));
	}

	if (p->peer_delay_resp) {
		msg_put(p->peer_delay_resp);
	}
	msg_get(m);
	p->peer_delay_resp = m;
	port_peer_delay(p);
	return 0;
}

void process_pdelay_resp_fup(struct port *p, struct ptp_message *m)
{
	if (!p->peer_delay_req) {
		return;
	}

	if (p->peer_delay_fup) {
		msg_put(p->peer_delay_fup);
	}

	msg_get(m);
	p->peer_delay_fup = m;
	port_peer_delay(p);
}

void process_sync(struct port *p, struct ptp_message *m)
{
	enum syfu_event event;
	switch (p->state) {
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_MASTER:
	case PS_GRAND_MASTER:
	case PS_PASSIVE:
		return;
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		break;
	}

	if (check_source_identity(p, m)) {
		return;
	}

	if (!msg_unicast(m) &&
	    m->header.logMessageInterval != p->log_sync_interval) {
		if (m->header.logMessageInterval < -10 ||
		    m->header.logMessageInterval > 22) {
			pl_info(300, "%s: ignore bogus sync interval 2^%d",
				p->log_name, m->header.logMessageInterval);
		} else {
			p->log_sync_interval = m->header.logMessageInterval;
			clock_sync_interval(p->clock, p->log_sync_interval);
		}
	}

	m->header.correction += p->asymmetry;

	if (one_step(m)) {
		port_synchronize(p, m->header.sequenceId,
				 m->hwts.ts, m->ts.pdu,
				 m->header.correction, 0,
				 m->header.logMessageInterval);
		flush_last_sync(p);
		return;
	}

	if (p->syfu == SF_HAVE_FUP &&
	    fup_sync_ok(p->last_syncfup, m) &&
	    p->last_syncfup->header.sequenceId == m->header.sequenceId) {
		event = SYNC_MATCH;
	} else {
		event = SYNC_MISMATCH;
	}
	port_syfufsm(p, event, m);
}

/* public methods */

void port_close(struct port *p)
{
	if (port_is_enabled(p)) {
		port_disable(p);
	}

	if (p->fda.fd[FD_RTNL] >= 0) {
		rtnl_close(p->fda.fd[FD_RTNL]);
	}

	unicast_client_cleanup(p);
	unicast_service_cleanup(p);
	transport_destroy(p->trp);
	tsproc_destroy(p->tsproc);
	if (p->fault_fd >= 0) {
		close(p->fault_fd);
	}
	free(p->log_name);
	free(p);
}

struct foreign_clock *port_compute_best(struct port *p)
{
	int (*dscmp)(struct dataset *a, struct dataset *b);
	struct foreign_clock *fc;
	struct ptp_message *tmp;

	dscmp = clock_dscmp(p->clock);
	p->best = NULL;

	if (p->master_only)
		return p->best;

	LIST_FOREACH(fc, &p->foreign_masters, list) {
		tmp = TAILQ_FIRST(&fc->messages);
		if (!tmp)
			continue;

		announce_to_dataset(tmp, p, &fc->dataset);

		fc_prune(fc);

		if (fc->n_messages < FOREIGN_MASTER_THRESHOLD)
			continue;

		if (!p->best)
			p->best = fc;
		else if (dscmp(&fc->dataset, &p->best->dataset) > 0)
			p->best = fc;
		else
			fc_clear(fc);
	}

	return p->best;
}

static void port_e2e_transition(struct port *p, enum port_state next)
{
	port_clr_tmo(p->fda.fd[FD_ANNOUNCE_TIMER]);
	port_clr_tmo(p->fda.fd[FD_SYNC_RX_TIMER]);
	port_clr_tmo(p->fda.fd[FD_DELAY_TIMER]);
	port_clr_tmo(p->fda.fd[FD_QUALIFICATION_TIMER]);
	port_clr_tmo(p->fda.fd[FD_MANNO_TIMER]);
	port_clr_tmo(p->fda.fd[FD_SYNC_TX_TIMER]);
	/* Leave FD_UNICAST_REQ_TIMER running. */

	switch (next) {
	case PS_INITIALIZING:
		break;
	case PS_FAULTY:
	case PS_DISABLED:
		port_disable(p);
		break;
	case PS_LISTENING:
		port_set_announce_tmo(p);
		break;
	case PS_PRE_MASTER:
		port_set_qualification_tmo(p);
		break;
	case PS_MASTER:
	case PS_GRAND_MASTER:
		if (!p->inhibit_announce) {
			set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, -10); /*~1ms*/
		}
		port_set_sync_tx_tmo(p);
		break;
	case PS_PASSIVE:
		port_set_announce_tmo(p);
		break;
	case PS_UNCALIBRATED:
		flush_last_sync(p);
		flush_delay_req(p);
		/* fall through */
	case PS_SLAVE:
		port_set_announce_tmo(p);
		port_set_delay_tmo(p);
		break;
	};
}

static void port_p2p_transition(struct port *p, enum port_state next)
{
	port_clr_tmo(p->fda.fd[FD_ANNOUNCE_TIMER]);
	port_clr_tmo(p->fda.fd[FD_SYNC_RX_TIMER]);
	/* Leave FD_DELAY_TIMER running. */
	port_clr_tmo(p->fda.fd[FD_QUALIFICATION_TIMER]);
	port_clr_tmo(p->fda.fd[FD_MANNO_TIMER]);
	port_clr_tmo(p->fda.fd[FD_SYNC_TX_TIMER]);
	/* Leave FD_UNICAST_REQ_TIMER running. */

	switch (next) {
	case PS_INITIALIZING:
		break;
	case PS_FAULTY:
	case PS_DISABLED:
		port_disable(p);
		break;
	case PS_LISTENING:
		port_set_announce_tmo(p);
		port_set_delay_tmo(p);
		break;
	case PS_PRE_MASTER:
		port_set_qualification_tmo(p);
		break;
	case PS_MASTER:
	case PS_GRAND_MASTER:
		if (!p->inhibit_announce) {
			set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, -10); /*~1ms*/
		}
		port_set_sync_tx_tmo(p);
		break;
	case PS_PASSIVE:
		port_set_announce_tmo(p);
		break;
	case PS_UNCALIBRATED:
		flush_last_sync(p);
		flush_peer_delay(p);
		/* fall through */
	case PS_SLAVE:
		port_set_announce_tmo(p);
		break;
	};
}

void port_dispatch(struct port *p, enum fsm_event event, int mdiff)
{
	p->dispatch(p, event, mdiff);
}

static void bc_dispatch(struct port *p, enum fsm_event event, int mdiff)
{
	if (clock_slave_only(p->clock)) {
		if (event == EV_RS_GRAND_MASTER) {
			port_slave_priority_warning(p);
		}
	}

	if (!port_state_update(p, event, mdiff)) {
		return;
	}

	if (p->delayMechanism == DM_P2P) {
		port_p2p_transition(p, p->state);
	} else {
		port_e2e_transition(p, p->state);
	}

	if (p->jbod && p->state == PS_UNCALIBRATED) {
		if (clock_switch_phc(p->clock, p->phc_index)) {
			p->last_fault_type = FT_SWITCH_PHC;
			port_dispatch(p, EV_FAULT_DETECTED, 0);
			return;
		}
		clock_sync_interval(p->clock, p->log_sync_interval);
	}
}

void port_link_status(void *ctx, int linkup, int ts_index)
{
	char ts_label[MAX_IFNAME_SIZE + 1] = {0};
	int link_state, required_modes;
	const char *old_ts_label;
	struct port *p = ctx;

	link_state = linkup ? LINK_UP : LINK_DOWN;
	if (p->link_status & link_state) {
		p->link_status = link_state;
	} else {
		p->link_status = link_state | LINK_STATE_CHANGED;
		pr_notice("%s: link %s", p->log_name, linkup ? "up" : "down");
	}

	/* ts_label changed */
	old_ts_label = interface_label(p->iface);
	if (if_indextoname(ts_index, ts_label) && strcmp(old_ts_label, ts_label)) {
		interface_set_label(p->iface, ts_label);
		p->link_status |= TS_LABEL_CHANGED;
		pr_notice("%s: ts label changed to %s", p->log_name, ts_label);
	}

	/* Both link down/up and change ts_label may change phc index. */
	if (p->link_status & LINK_UP &&
	    (p->link_status & LINK_STATE_CHANGED || p->link_status & TS_LABEL_CHANGED)) {
		interface_get_tsinfo(p->iface);

		/* Only switch phc with HW time stamping mode */
		if (interface_tsinfo_valid(p->iface) &&
		    interface_phc_index(p->iface) >= 0) {
			required_modes = clock_required_modes(p->clock);
			if (!interface_tsmodes_supported(p->iface, required_modes)) {
				pr_err("interface '%s' does not support requested "
				       "timestamping mode, set link status down by force.",
				       interface_label(p->iface));
				p->link_status = LINK_DOWN | LINK_STATE_CHANGED;
			} else if (p->phc_from_cmdline) {
				pr_warning("%s: taking /dev/ptp%d from the "
					   "command line, not the attached ptp%d",
					   p->log_name, p->phc_index,
					   interface_phc_index(p->iface));
			} else if (p->phc_index != interface_phc_index(p->iface)) {
				p->phc_index = interface_phc_index(p->iface);

				if (clock_switch_phc(p->clock, p->phc_index)) {
					p->last_fault_type = FT_SWITCH_PHC;
					port_dispatch(p, EV_FAULT_DETECTED, 0);
					return;
				}
				clock_sync_interval(p->clock, p->log_sync_interval);
			}
		}
	}

	/*
	 * A port going down can affect the BMCA result.
	 * Force a state decision event.
	 */
	if (p->link_status & LINK_DOWN)
		clock_set_sde(p->clock, 1);
}

enum fsm_event port_event(struct port *p, int fd_index)
{
	return p->event(p, fd_index);
}

static enum fsm_event bc_event(struct port *p, int fd_index)
{
	enum fsm_event event = EV_NONE;
	struct ptp_message *msg;
	int cnt, fd = p->fda.fd[fd_index], err;

	switch (fd_index) {
	case FD_ANNOUNCE_TIMER:
	case FD_SYNC_RX_TIMER:
		pr_debug("%s: %s timeout", p->log_name,
			 fd_index == FD_SYNC_RX_TIMER ? "rx sync" : "announce");
		if (p->best) {
			fc_clear(p->best);
		}

		/*
		 * Clear out the event returned by poll(). It is only cleared
		 * in port_*_transition(). But, when BMCA == 'noop', there is no
		 * state transition. So, it won't be cleared anywhere else.
		 */
		if (p->bmca == BMCA_NOOP) {
			port_clr_tmo(p->fda.fd[FD_SYNC_RX_TIMER]);
		}

		if (p->inhibit_announce) {
			port_clr_tmo(p->fda.fd[FD_ANNOUNCE_TIMER]);
		} else {
			port_set_announce_tmo(p);
		}

		delay_req_prune(p);
		if (clock_slave_only(p->clock) && p->delayMechanism != DM_P2P &&
		    port_renew_transport(p)) {
			return EV_FAULT_DETECTED;
		}

		if (p->inhibit_announce) {
			return EV_NONE;
		}
		return EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES;

	case FD_DELAY_TIMER:
		pr_debug("%s: delay timeout", p->log_name);
		port_set_delay_tmo(p);
		delay_req_prune(p);
		if (port_delay_request(p)) {
			return EV_FAULT_DETECTED;
		}
		if (p->delay_response_timeout && p->state == PS_SLAVE) {
			p->delay_response_counter++;
			if (p->delay_response_counter >= p->delay_response_timeout) {
				p->delay_response_counter = 0;
				tsproc_reset(clock_get_tsproc(p->clock), 1);
				pr_err("%s: delay response timeout", p->log_name);
				return EV_SYNCHRONIZATION_FAULT;
			}
		}
		return EV_NONE;

	case FD_QUALIFICATION_TIMER:
		pr_debug("%s: qualification timeout", p->log_name);
		return EV_QUALIFICATION_TIMEOUT_EXPIRES;

	case FD_MANNO_TIMER:
		pr_debug("%s: master tx announce timeout", p->log_name);
		port_set_manno_tmo(p);
		clock_update_leap_status(p->clock);
		return port_tx_announce(p, NULL) ? EV_FAULT_DETECTED : EV_NONE;

	case FD_SYNC_TX_TIMER:
		pr_debug("%s: master sync timeout", p->log_name);
		port_set_sync_tx_tmo(p);
		return port_tx_sync(p, NULL) ? EV_FAULT_DETECTED : EV_NONE;

	case FD_UNICAST_SRV_TIMER:
		pr_debug("%s: unicast service timeout", p->log_name);
		return unicast_service_timer(p) ? EV_FAULT_DETECTED : EV_NONE;

	case FD_UNICAST_REQ_TIMER:
		pr_debug("%s: unicast request timeout", p->log_name);
		return unicast_client_timer(p) ? EV_FAULT_DETECTED : EV_NONE;

	case FD_RTNL:
		pr_debug("%s: received link status notification", p->log_name);
		rtnl_link_status(fd, p->name, port_link_status, p);
		if (p->link_status == (LINK_UP | LINK_STATE_CHANGED))
			return EV_FAULT_CLEARED;
		else if ((p->link_status == (LINK_DOWN | LINK_STATE_CHANGED)) ||
			 (p->link_status & TS_LABEL_CHANGED))
			return EV_FAULT_DETECTED;
		else
			return EV_NONE;
	}

	msg = msg_allocate();
	if (!msg)
		return EV_FAULT_DETECTED;

	msg->hwts.type = p->timestamping;

	cnt = transport_recv(p->trp, fd, msg);
	if (cnt < 0) {
		pr_err("%s: recv message failed", p->log_name);
		msg_put(msg);
		return EV_FAULT_DETECTED;
	}
	err = msg_post_recv(msg, cnt);
	if (err) {
		switch (err) {
		case -EBADMSG:
			pr_err("%s: bad message", p->log_name);
			break;
		case -EPROTO:
			pr_debug("%s: ignoring message", p->log_name);
			break;
		}
		msg_put(msg);
		return EV_NONE;
	}
	port_stats_inc_rx(p, msg);
	if (port_ignore(p, msg)) {
		msg_put(msg);
		return EV_NONE;
	}
	if (msg_sots_missing(msg) &&
	    !(p->timestamping == TS_P2P1STEP && msg_type(msg) == PDELAY_REQ)) {
		pr_err("%s: received %s without timestamp",
		       p->log_name, msg_type_string(msg_type(msg)));
		msg_put(msg);
		return EV_NONE;
	}
	if (msg_sots_valid(msg)) {
		ts_add(&msg->hwts.ts, -p->rx_timestamp_offset);
		if (p->state == PS_SLAVE) {
			clock_check_ts(p->clock,
				       tmv_to_nanoseconds(msg->hwts.ts));
		}
	}

	switch (msg_type(msg)) {
	case SYNC:
		process_sync(p, msg);
		break;
	case DELAY_REQ:
		if (process_delay_req(p, msg))
			event = EV_FAULT_DETECTED;
		break;
	case PDELAY_REQ:
		if (process_pdelay_req(p, msg))
			event = EV_FAULT_DETECTED;
		break;
	case PDELAY_RESP:
		if (process_pdelay_resp(p, msg))
			event = EV_FAULT_DETECTED;
		break;
	case FOLLOW_UP:
		process_follow_up(p, msg);
		break;
	case DELAY_RESP:
		process_delay_resp(p, msg);
		break;
	case PDELAY_RESP_FOLLOW_UP:
		process_pdelay_resp_fup(p, msg);
		break;
	case ANNOUNCE:
		if (process_announce(p, msg))
			event = EV_STATE_DECISION_EVENT;
		break;
	case SIGNALING:
		if (process_signaling(p, msg)) {
			event = EV_FAULT_DETECTED;
		}
		break;
	case MANAGEMENT:
		if (clock_manage(p->clock, p, msg))
			event = EV_STATE_DECISION_EVENT;
		break;
	}

	msg_put(msg);
	return event;
}

int port_forward(struct port *p, struct ptp_message *msg)
{
	int cnt;
	cnt = transport_send(p->trp, &p->fda, TRANS_GENERAL, msg);
	if (cnt <= 0) {
		return -1;
	}
	port_stats_inc_tx(p, msg);
	return 0;
}

int port_forward_to(struct port *p, struct ptp_message *msg)
{
	int cnt;
	cnt = transport_sendto(p->trp, &p->fda, TRANS_GENERAL, msg);
	if (cnt < 0) {
		return cnt;
	} else if (!cnt) {
		return -EIO;
	}
	port_stats_inc_tx(p, msg);
	return 0;
}

int port_prepare_and_send(struct port *p, struct ptp_message *msg,
			  enum transport_event event)
{
	int cnt;

	if (msg_pre_send(msg)) {
		return -1;
	}
	if (msg_unicast(msg)) {
		cnt = transport_sendto(p->trp, &p->fda, event, msg);
	} else {
		cnt = transport_send(p->trp, &p->fda, event, msg);
	}
	if (cnt <= 0) {
		return -1;
	}
	port_stats_inc_tx(p, msg);
	if (msg_sots_valid(msg)) {
		ts_add(&msg->hwts.ts, p->tx_timestamp_offset);
	}
	return 0;
}

struct PortIdentity port_identity(struct port *p)
{
	return p->portIdentity;
}

int port_number(struct port *p)
{
	return portnum(p);
}

const char *port_log_name(struct port *p)
{
	return p->log_name;
}

int port_link_status_get(struct port *p)
{
	return !!(p->link_status & LINK_UP);
}

int port_manage(struct port *p, struct port *ingress, struct ptp_message *msg)
{
	struct management_tlv *mgt;
	UInteger16 target = msg->management.targetPortIdentity.portNumber;

	if (target != portnum(p) && target != 0xffff) {
		return 0;
	}
	mgt = (struct management_tlv *) msg->management.suffix;

	switch (management_action(msg)) {
	case GET:
		if (port_management_get_response(p, ingress, mgt->id, msg))
			return 1;
		break;
	case SET:
		if (port_management_set(p, ingress, mgt->id, msg))
			return 1;
		break;
	case COMMAND:
		break;
	default:
		return -1;
	}

	switch (mgt->id) {
	case MID_NULL_MANAGEMENT:
	case MID_CLOCK_DESCRIPTION:
	case MID_PORT_DATA_SET:
	case MID_LOG_ANNOUNCE_INTERVAL:
	case MID_ANNOUNCE_RECEIPT_TIMEOUT:
	case MID_LOG_SYNC_INTERVAL:
	case MID_VERSION_NUMBER:
	case MID_ENABLE_PORT:
	case MID_DISABLE_PORT:
	case MID_UNICAST_NEGOTIATION_ENABLE:
	case MID_UNICAST_MASTER_TABLE:
	case MID_UNICAST_MASTER_MAX_TABLE_SIZE:
	case MID_ACCEPTABLE_MASTER_TABLE_ENABLED:
	case MID_ALTERNATE_MASTER:
	case MID_MASTER_ONLY:
	case MID_TRANSPARENT_CLOCK_PORT_DATA_SET:
	case MID_DELAY_MECHANISM:
	case MID_LOG_MIN_PDELAY_REQ_INTERVAL:
		port_management_send_error(p, ingress, msg, MID_NOT_SUPPORTED);
		break;
	default:
		port_management_send_error(p, ingress, msg, MID_NO_SUCH_ID);
		return -1;
	}
	return 1;
}

int port_management_error(struct PortIdentity pid, struct port *ingress,
			  struct ptp_message *req, Enumeration16 error_id)
{
	struct management_error_status *mes;
	struct management_tlv *mgt;
	struct ptp_message *msg;
	struct tlv_extra *extra;
	int err = 0;

	mgt = (struct management_tlv *) req->management.suffix;
	msg = port_management_reply(pid, ingress, req);
	if (!msg) {
		return -1;
	}

	extra = msg_tlv_append(msg, sizeof(*mes));
	if (!extra) {
		msg_put(msg);
		return -ENOMEM;
	}
	mes = (struct management_error_status *) extra->tlv;
	mes->type = TLV_MANAGEMENT_ERROR_STATUS;
	mes->length = 8;
	mes->error = error_id;
	mes->id = mgt->id;

	err = port_prepare_and_send(ingress, msg, TRANS_GENERAL);
	msg_put(msg);
	return err;
}

static struct ptp_message *
port_management_construct(struct PortIdentity pid, struct port *ingress,
			  UInteger16 sequenceId,
			  struct PortIdentity *targetPortIdentity,
			  UInteger8 boundaryHops, uint8_t action)
{
	struct ptp_message *msg;

	msg = msg_allocate();
	if (!msg)
		return NULL;

	msg->hwts.type = ingress->timestamping;

	msg->header.tsmt               = MANAGEMENT | ingress->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct management_msg);
	msg->header.domainNumber       = clock_domain_number(ingress->clock);
	msg->header.sourcePortIdentity = pid;
	msg->header.sequenceId         = sequenceId;
	msg->header.control            = CTL_MANAGEMENT;
	msg->header.logMessageInterval = 0x7f;

	if (targetPortIdentity)
		msg->management.targetPortIdentity = *targetPortIdentity;
	msg->management.startingBoundaryHops = boundaryHops;
	msg->management.boundaryHops = boundaryHops;

	switch (action) {
	case GET: case SET:
		msg->management.flags = RESPONSE;
		break;
	case COMMAND:
		msg->management.flags = ACKNOWLEDGE;
		break;
	}
	return msg;
}

struct ptp_message *port_management_reply(struct PortIdentity pid,
					  struct port *ingress,
					  struct ptp_message *req)
{
	UInteger8 boundaryHops;

	boundaryHops = req->management.startingBoundaryHops -
		       req->management.boundaryHops;
	return port_management_construct(pid, ingress,
					 req->header.sequenceId,
					 &req->header.sourcePortIdentity,
					 boundaryHops,
					 management_action(req));
}

struct ptp_message *port_management_notify(struct PortIdentity pid,
					   struct port *port)
{
	return port_management_construct(pid, port, 0, NULL, 1, GET);
}

void port_notify_event(struct port *p, enum notification event)
{
	struct PortIdentity pid = port_identity(p);
	struct ptp_message *msg;
	int id;

	switch (event) {
	case NOTIFY_PORT_STATE:
		id = MID_PORT_DATA_SET;
		break;
	default:
		return;
	}
	/* targetPortIdentity and sequenceId will be filled by
	 * clock_send_notification */
	msg = port_management_notify(pid, p);
	if (!msg)
		return;
	if (!port_management_fill_response(p, msg, id))
		goto err;
	if (msg_pre_send(msg))
		goto err;
	clock_send_notification(p->clock, msg, event);
err:
	msg_put(msg);
}

struct port *port_open(const char *phc_device,
		       int phc_index,
		       enum timestamp_type timestamping,
		       int number,
		       struct interface *interface,
		       struct clock *clock)
{
	enum clock_type type = clock_type(clock);
	struct config *cfg = clock_config(clock);
	struct port *p = malloc(sizeof(*p));
	int i;

	if (!p) {
		return NULL;
	}

	memset(p, 0, sizeof(*p));
	TAILQ_INIT(&p->tc_transmitted);

	p->name = interface_name(interface);
	if (asprintf(&p->log_name, "port %d (%s)", number, p->name) == -1) {
		p->log_name = NULL;
		goto err_port;
	}

	switch (type) {
	case CLOCK_TYPE_ORDINARY:
	case CLOCK_TYPE_BOUNDARY:
		p->dispatch = bc_dispatch;
		p->event = bc_event;
		break;
	case CLOCK_TYPE_P2P:
		p->dispatch = p2p_dispatch;
		p->event = p2p_event;
		break;
	case CLOCK_TYPE_E2E:
		p->dispatch = e2e_dispatch;
		p->event = e2e_event;
		break;
	case CLOCK_TYPE_MANAGEMENT:
		goto err_log_name;
	}

	p->phc_index = phc_index;
	p->jbod = config_get_int(cfg, interface_name(interface), "boundary_clock_jbod");
	p->master_only = config_get_int(cfg, interface_name(interface), "serverOnly");
	p->bmca = config_get_int(cfg, interface_name(interface), "BMCA");
	p->trp = transport_create(cfg, config_get_int(cfg,
			      interface_name(interface), "network_transport"));
	if (!p->trp) {
		goto err_log_name;
	}

	if (p->bmca == BMCA_NOOP && !port_is_uds(p)) {
		if (p->master_only) {
			p->state_machine = designated_master_fsm;
		} else if (clock_slave_only(clock)) {
			p->state_machine = designated_slave_fsm;
		} else {
			pr_err("Please enable at least one of serverOnly or clientOnly when BMCA == noop.\n");
			goto err_transport;
		}
	} else {
		p->state_machine = clock_slave_only(clock) ? ptp_slave_fsm : ptp_fsm;
	}

	if (port_is_uds(p)) {
		; /* UDS cannot have a PHC. */
	} else if (!interface_tsinfo_valid(interface)) {
		pr_warning("%s: get_ts_info not supported", p->log_name);
	} else if (phc_index >= 0 &&
		   phc_index != interface_phc_index(interface)) {
		if (p->jbod) {
			pr_warning("%s: just a bunch of devices", p->log_name);
			p->phc_index = interface_phc_index(interface);
		} else if (phc_device) {
			pr_warning("%s: taking %s from the command line, "
				   "not the attached ptp%d", p->log_name,
				   phc_device, interface_phc_index(interface));
			p->phc_index = phc_index;
			p->phc_from_cmdline = 1;
		} else {
			pr_err("%s: PHC device mismatch", p->log_name);
			pr_err("%s: /dev/ptp%d requested, ptp%d attached",
			       p->log_name, phc_index,
			       interface_phc_index(interface));
			goto err_transport;
		}
	}

	p->iface = interface;
	p->asymmetry = config_get_int(cfg, p->name, "delayAsymmetry");
	p->asymmetry <<= 16;
	p->announce_span = port_is_uds(p) ? 0 : ANNOUNCE_SPAN;
	p->follow_up_info = config_get_int(cfg, p->name, "follow_up_info");
	p->freq_est_interval = config_get_int(cfg, p->name, "freq_est_interval");
	p->msg_interval_request = config_get_int(cfg, p->name, "msg_interval_request");
	p->net_sync_monitor = config_get_int(cfg, p->name, "net_sync_monitor");
	p->path_trace_enabled = config_get_int(cfg, p->name, "path_trace_enabled");
	p->tc_spanning_tree = config_get_int(cfg, p->name, "tc_spanning_tree");
	p->rx_timestamp_offset = config_get_int(cfg, p->name, "ingressLatency");
	p->rx_timestamp_offset <<= 16;
	p->tx_timestamp_offset = config_get_int(cfg, p->name, "egressLatency");
	p->tx_timestamp_offset <<= 16;
	p->link_status = LINK_UP;
	p->clock = clock;
	p->timestamping = timestamping;
	p->portIdentity.clockIdentity = clock_identity(clock);
	p->portIdentity.portNumber = number;
	p->state = PS_INITIALIZING;
	p->delayMechanism = config_get_int(cfg, p->name, "delay_mechanism");
	p->versionNumber = PTP_MAJOR_VERSION;
	p->slave_event_monitor = clock_slave_monitor(clock);

	if (!port_is_uds(p) && unicast_client_initialize(p)) {
		goto err_transport;
	}
	if (unicast_client_enabled(p) &&
	    config_set_section_int(cfg, p->name, "hybrid_e2e", 1)) {
		goto err_uc_client;
	}
	if (!port_is_uds(p) && unicast_service_initialize(p)) {
		goto err_uc_client;
	}
	p->hybrid_e2e = config_get_int(cfg, p->name, "hybrid_e2e");

	if (!port_is_uds(p) && type == CLOCK_TYPE_P2P &&
	    p->delayMechanism != DM_P2P) {
		pr_err("%s: P2P TC needs P2P ports", p->log_name);
		goto err_uc_service;
	}
	if (!port_is_uds(p) && type == CLOCK_TYPE_E2E &&
	    p->delayMechanism != DM_E2E) {
		pr_err("%s: E2E TC needs E2E ports", p->log_name);
		goto err_uc_service;
	}
	if (p->hybrid_e2e && p->delayMechanism != DM_E2E) {
		pr_warning("%s: hybrid_e2e only works with E2E", p->log_name);
	}
	if (p->net_sync_monitor && !p->hybrid_e2e) {
		pr_warning("%s: net_sync_monitor needs hybrid_e2e", p->log_name);
	}

	/* Set fault timeouts to a default value */
	for (i = 0; i < FT_CNT; i++) {
		p->flt_interval_pertype[i].type = FTMO_LOG2_SECONDS;
		p->flt_interval_pertype[i].val = 4;
	}
	p->flt_interval_pertype[FT_BAD_PEER_NETWORK].type = FTMO_LINEAR_SECONDS;
	p->flt_interval_pertype[FT_BAD_PEER_NETWORK].val =
		config_get_int(cfg, p->name, "fault_badpeernet_interval");

	p->flt_interval_pertype[FT_UNSPECIFIED].val =
		config_get_int(cfg, p->name, "fault_reset_interval");

	p->tsproc = tsproc_create(config_get_int(cfg, p->name, "tsproc_mode"),
				  config_get_int(cfg, p->name, "delay_filter"),
				  config_get_int(cfg, p->name, "delay_filter_length"));
	if (!p->tsproc) {
		pr_err("Failed to create time stamp processor");
		goto err_uc_service;
	}
	p->nrate.ratio = 1.0;

	port_clear_fda(p, N_POLLFD);
	p->fault_fd = -1;
	if (!port_is_uds(p)) {
		p->fault_fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (p->fault_fd < 0) {
			pr_err("timerfd_create failed: %m");
			goto err_tsproc;
		}
	}
	return p;

err_tsproc:
	tsproc_destroy(p->tsproc);
err_uc_service:
	unicast_service_cleanup(p);
err_uc_client:
	unicast_client_cleanup(p);
err_transport:
	transport_destroy(p->trp);
err_log_name:
	free(p->log_name);
err_port:
	free(p);
	return NULL;
}

enum port_state port_state(struct port *port)
{
	return port->state;
}

int port_state_update(struct port *p, enum fsm_event event, int mdiff)
{
	enum port_state next = p->state_machine(p->state, event, mdiff);

	if (PS_FAULTY == next) {
		struct fault_interval i;
		fault_interval(p, last_fault_type(p), &i);
		if (clear_fault_asap(&i)) {
			pr_notice("%s: clearing fault immediately", p->log_name);
			next = p->state_machine(next, EV_FAULT_CLEARED, 0);
		}
	}

	if (PS_INITIALIZING == next) {
		/*
		 * This is a special case. Since we initialize the
		 * port immediately, we can skip right to listening
		 * state if all goes well.
		 */
		if (port_is_enabled(p)) {
			port_disable(p);
		}
		if (port_initialize(p)) {
			event = EV_FAULT_DETECTED;
		} else {
			event = EV_INIT_COMPLETE;
		}
		next = p->state_machine(next, event, 0);
	}

	if (mdiff) {
		unicast_client_state_changed(p);
	}
	if (next != p->state) {
		port_show_transition(p, next, event);
		p->state = next;
		port_notify_event(p, NOTIFY_PORT_STATE);
		unicast_client_state_changed(p);
		return 1;
	}

	return 0;
}

enum bmca_select port_bmca(struct port *p)
{
	return p->bmca;
}
