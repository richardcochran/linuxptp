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

#include "bmc.h"
#include "clock.h"
#include "filter.h"
#include "missing.h"
#include "msg.h"
#include "port.h"
#include "print.h"
#include "sk.h"
#include "tlv.h"
#include "tmv.h"
#include "util.h"

#define ALLOWED_LOST_RESPONSES 3

enum syfu_state {
	SF_EMPTY,
	SF_HAVE_SYNC,
	SF_HAVE_FUP,
};

enum syfu_event {
	SYNC_MISMATCH,
	SYNC_MATCH,
	FUP_MISMATCH,
	FUP_MATCH,
};

struct nrate_estimator {
	double ratio;
	tmv_t origin1;
	tmv_t ingress1;
	unsigned int max_count;
	unsigned int count;
	int ratio_valid;
};

struct port {
	char *name;
	struct clock *clock;
	struct transport *trp;
	enum timestamp_type timestamping;
	struct fdarray fda;
	struct foreign_clock *best;
	enum syfu_state syfu;
	struct ptp_message *last_syncfup;
	struct ptp_message *delay_req;
	struct ptp_message *peer_delay_req;
	struct ptp_message *peer_delay_resp;
	struct ptp_message *peer_delay_fup;
	int peer_portid_valid;
	struct PortIdentity peer_portid;
	struct {
		UInteger16 announce;
		UInteger16 delayreq;
		UInteger16 sync;
	} seqnum;
	tmv_t peer_delay;
	struct filter *delay_filter;
	int log_sync_interval;
	struct nrate_estimator nrate;
	unsigned int pdr_missing;
	unsigned int multiple_seq_pdr_count;
	unsigned int multiple_pdr_detected;
	/* portDS */
	struct port_defaults pod;
	struct PortIdentity portIdentity;
	enum port_state     state; /*portState*/
	int                 asCapable;
	Integer8            logMinDelayReqInterval;
	TimeInterval        peerMeanPathDelay;
	Integer8            logAnnounceInterval;
	UInteger8           announceReceiptTimeout;
	UInteger8           syncReceiptTimeout;
	UInteger8           transportSpecific;
	Integer8            logSyncInterval;
	Enumeration8        delayMechanism;
	Integer8            logMinPdelayReqInterval;
	UInteger32          neighborPropDelayThresh;
	int                 min_neighbor_prop_delay;
	enum fault_type     last_fault_type;
	unsigned int        versionNumber; /*UInteger4*/
	/* foreignMasterDS */
	LIST_HEAD(fm, foreign_clock) foreign_masters;
};

#define portnum(p) (p->portIdentity.portNumber)

#define NSEC2SEC 1000000000LL

static int port_capable(struct port *p);
static int port_is_ieee8021as(struct port *p);
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

static void announce_to_dataset(struct ptp_message *m, struct clock *c,
				struct dataset *out)
{
	struct announce_msg *a = &m->announce;
	out->priority1    = a->grandmasterPriority1;
	out->identity     = a->grandmasterIdentity;
	out->quality      = a->grandmasterClockQuality;
	out->priority2    = a->grandmasterPriority2;
	out->stepsRemoved = a->stepsRemoved;
	out->sender       = m->header.sourcePortIdentity;
	out->receiver     = clock_parent_identity(c);
}

static int msg_current(struct ptp_message *m, struct timespec now)
{
	int64_t t1, t2, tmo;

	t1 = m->ts.host.tv_sec * NSEC2SEC + m->ts.host.tv_nsec;
	t2 = now.tv_sec * NSEC2SEC + now.tv_nsec;

	if (m->header.logMessageInterval < 0)
		tmo = 4LL * NSEC2SEC / (1 << -m->header.logMessageInterval);
	else
		tmo = 4LL * (1 << m->header.logMessageInterval) * NSEC2SEC;

	return t2 - t1 < tmo;
}

static int msg_source_equal(struct ptp_message *m1, struct foreign_clock *fc)
{
	struct PortIdentity *id1, *id2;
	id1 = &m1->header.sourcePortIdentity;
	id2 = &fc->dataset.sender;
	return 0 == memcmp(id1, id2, sizeof(*id1));
}

static int pid_eq(struct PortIdentity *a, struct PortIdentity *b)
{
	return 0 == memcmp(a, b, sizeof(*a));
}

static int source_pid_eq(struct ptp_message *m1, struct ptp_message *m2)
{
	return pid_eq(&m1->header.sourcePortIdentity,
		      &m2->header.sourcePortIdentity);
}

enum fault_type last_fault_type(struct port *port)
{
	return port->last_fault_type;
}

int fault_interval(struct port *port, enum fault_type ft,
	struct fault_interval *i)
{
	if (!port || !i)
		return -EINVAL;
	if (ft < 0 || ft >= FT_CNT)
		return -EINVAL;
	i->type = port->pod.flt_interval_pertype[ft].type;
	i->val = port->pod.flt_interval_pertype[ft].val;
	return 0;
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

static void fc_clear(struct foreign_clock *fc)
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

static void ts_to_timestamp(struct timespec *src, struct Timestamp *dst)
{
	dst->seconds_lsb = src->tv_sec;
	dst->seconds_msb = 0;
	dst->nanoseconds = src->tv_nsec;
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
		if (msg_source_equal(m, fc))
			break;
	}
	if (!fc) {
		pr_notice("port %hu: new foreign master %s", portnum(p),
			pid2str(&m->header.sourcePortIdentity));

		fc = malloc(sizeof(*fc));
		if (!fc) {
			pr_err("low memory, failed to add foreign master");
			return 0;
		}
		memset(fc, 0, sizeof(*fc));
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
	if (FOREIGN_MASTER_THRESHOLD - 1 == fc->n_messages)
		broke_threshold = 1;

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

static int follow_up_info_append(struct port *p, struct ptp_message *m)
{
	struct follow_up_info_tlv *fui;
	fui = (struct follow_up_info_tlv *) m->follow_up.suffix;
	fui->type = TLV_ORGANIZATION_EXTENSION;
	fui->length = sizeof(*fui) - sizeof(fui->type) - sizeof(fui->length);
	memcpy(fui->id, ieee8021_id, sizeof(ieee8021_id));
	fui->subtype[2] = 1;
	m->tlv_count = 1;
	return sizeof(*fui);
}

static struct follow_up_info_tlv *follow_up_info_extract(struct ptp_message *m)
{
	struct follow_up_info_tlv *f;
	f = (struct follow_up_info_tlv *) m->follow_up.suffix;

	if (m->tlv_count != 1 ||
	    f->type != TLV_ORGANIZATION_EXTENSION ||
	    f->length != sizeof(*f) - sizeof(f->type) - sizeof(f->length) ||
//	    memcmp(f->id, ieee8021_id, sizeof(ieee8021_id)) ||
	    f->subtype[0] || f->subtype[1] || f->subtype[2] != 1) {
		return NULL;
	}
	return f;
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
	int64_t tfup, tsync;
	tfup = tmv_to_nanoseconds(timespec_to_tmv(fup->hwts.sw));
	tsync = tmv_to_nanoseconds(timespec_to_tmv(sync->hwts.sw));
	/*
	 * NB - If the sk_check_fupsync option is not enabled, then
	 * both of these time stamps will be zero.
	 */
	if (tfup < tsync) {
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
	struct path_trace_tlv *ptt;
	int length = 1 + dad->path_length;

	if (length > PATH_TRACE_MAX) {
		return 0;
	}
	ptt = (struct path_trace_tlv *) m->announce.suffix;
	ptt->type = TLV_PATH_TRACE;
	ptt->length = length * sizeof(struct ClockIdentity);
	memcpy(ptt->cid, dad->ptl, ptt->length);
	ptt->cid[length - 1] = clock_identity(p->clock);
	m->tlv_count = 1;
	return ptt->length + sizeof(ptt->type) + sizeof(ptt->length);
}

static int path_trace_ignore(struct port *p, struct ptp_message *m)
{
	struct ClockIdentity cid;
	struct path_trace_tlv *ptt;
	int i, cnt;

	if (!p->pod.path_trace_enabled) {
		return 0;
	}
	if (msg_type(m) != ANNOUNCE) {
		return 0;
	}
	if (m->tlv_count != 1) {
		return 1;
	}
	ptt = (struct path_trace_tlv *) m->announce.suffix;
	if (ptt->type != TLV_PATH_TRACE) {
		return 1;
	}
	cnt = path_length(ptt);
	cid = clock_identity(p->clock);
	for (i = 0; i < cnt; i++) {
		if (0 == memcmp(&ptt->cid[i], &cid, sizeof(cid)))
			return 1;
	}
	return 0;
}

static int port_capable(struct port *p)
{
	if (!port_is_ieee8021as(p)) {
		/* Normal 1588 ports are always capable. */
		goto capable;
	}

	if (tmv_to_nanoseconds(p->peer_delay) >	p->neighborPropDelayThresh) {
		if (p->asCapable)
			pr_debug("port %hu: peer_delay (%" PRId64 ") > neighborPropDelayThresh "
				"(%" PRId32 "), resetting asCapable", portnum(p),
				tmv_to_nanoseconds(p->peer_delay),
				p->neighborPropDelayThresh);
		goto not_capable;
	}

	if (tmv_to_nanoseconds(p->peer_delay) <	p->min_neighbor_prop_delay) {
		if (p->asCapable)
			pr_debug("port %hu: peer_delay (%" PRId64 ") < min_neighbor_prop_delay "
				"(%" PRId32 "), resetting asCapable", portnum(p),
				tmv_to_nanoseconds(p->peer_delay),
				p->min_neighbor_prop_delay);
		goto not_capable;
	}

	if (p->pdr_missing > ALLOWED_LOST_RESPONSES) {
		if (p->asCapable)
			pr_debug("port %hu: missed %d peer delay resp, "
				"resetting asCapable", portnum(p), p->pdr_missing);
		goto not_capable;
	}

	if (p->multiple_seq_pdr_count) {
		if (p->asCapable)
			pr_debug("port %hu: multiple sequential peer delay resp, "
				"resetting asCapable", portnum(p));
		goto not_capable;
	}

	if (!p->peer_portid_valid) {
		if (p->asCapable)
			pr_debug("port %hu: invalid peer port id, "
				"resetting asCapable", portnum(p));
		goto not_capable;
	}

	if (!p->nrate.ratio_valid) {
		if (p->asCapable)
			pr_debug("port %hu: invalid nrate, "
				"resetting asCapable", portnum(p));
		goto not_capable;
	}

capable:
	if (!p->asCapable)
		pr_debug("port %hu: setting asCapable", portnum(p));
	p->asCapable = 1;
	return 1;

not_capable:
	if (p->asCapable)
		port_nrate_initialize(p);
	p->asCapable = 0;
	return 0;
}

static int port_clr_tmo(int fd)
{
	struct itimerspec tmo = {
		{0, 0}, {0, 0}
	};
	return timerfd_settime(fd, 0, &tmo, NULL);
}

static int port_ignore(struct port *p, struct ptp_message *m)
{
	struct ClockIdentity c1, c2;

	if (incapable_ignore(p, m)) {
		return 1;
	}
	if (path_trace_ignore(p, m)) {
		return 1;
	}
	if (msg_transport_specific(m) != p->transportSpecific) {
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

	if (0 == memcmp(&c1, &c2, sizeof(c1))) {
		return 1;
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
	if (!memcmp(&cid, &pid.clockIdentity, sizeof(cid))) {
		/*
		 * We are the GM, but without gmCapable set.
		 */
		return 1;
	}
	return 0;
}

static int port_is_ieee8021as(struct port *p)
{
	return p->pod.follow_up_info ? 1 : 0;
}

static void port_management_send_error(struct port *p, struct port *ingress,
				       struct ptp_message *msg, int error_id)
{
	if (port_management_error(p->portIdentity, ingress, msg, error_id))
		pr_err("port %hu: management error failed", portnum(p));
}

static const Octet profile_id_drr[] = {0x00, 0x1B, 0x19, 0x00, 0x01, 0x00};
static const Octet profile_id_p2p[] = {0x00, 0x1B, 0x19, 0x00, 0x02, 0x00};

static int port_management_get_response(struct port *target,
					struct port *ingress, int id,
					struct ptp_message *req)
{
	int datalen = 0, err, pdulen, respond = 0;
	struct management_tlv *tlv;
	struct management_tlv_datum *mtd;
	struct ptp_message *rsp;
	struct portDS *pds;
	struct port_ds_np *pdsnp;
	struct PortIdentity pid = port_identity(target);
	struct clock_description *desc;
	struct mgmt_clock_description *cd;
	uint8_t *buf;
	uint16_t u16;

	rsp = port_management_reply(pid, ingress, req);
	if (!rsp) {
		return 0;
	}
	tlv = (struct management_tlv *) rsp->management.suffix;
	tlv->type = TLV_MANAGEMENT;
	tlv->id = id;

	switch (id) {
	case NULL_MANAGEMENT:
		datalen = 0;
		respond = 1;
		break;
	case CLOCK_DESCRIPTION:
		cd = &rsp->last_tlv.cd;
		buf = tlv->data;
		cd->clockType = (UInteger16 *) buf;
		buf += sizeof(*cd->clockType);
		if (clock_num_ports(target->clock) > 1) {
			*cd->clockType = CLOCK_TYPE_BOUNDARY;
		} else {
			*cd->clockType = CLOCK_TYPE_ORDINARY;
		}

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
		respond = 1;
		break;
	case PORT_DATA_SET:
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
		respond = 1;
		break;
	case LOG_ANNOUNCE_INTERVAL:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->logAnnounceInterval;
		datalen = sizeof(*mtd);
		respond = 1;
		break;
	case ANNOUNCE_RECEIPT_TIMEOUT:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->announceReceiptTimeout;
		datalen = sizeof(*mtd);
		respond = 1;
		break;
	case LOG_SYNC_INTERVAL:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->logSyncInterval;
		datalen = sizeof(*mtd);
		respond = 1;
		break;
	case VERSION_NUMBER:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->versionNumber;
		datalen = sizeof(*mtd);
		respond = 1;
		break;
	case DELAY_MECHANISM:
		mtd = (struct management_tlv_datum *) tlv->data;
		if (target->delayMechanism)
			mtd->val = target->delayMechanism;
		else
			mtd->val = DM_E2E;
		datalen = sizeof(*mtd);
		respond = 1;
		break;
	case LOG_MIN_PDELAY_REQ_INTERVAL:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = target->logMinPdelayReqInterval;
		datalen = sizeof(*mtd);
		respond = 1;
		break;
	case PORT_DATA_SET_NP:
		pdsnp = (struct port_ds_np *) tlv->data;
		pdsnp->neighborPropDelayThresh = target->neighborPropDelayThresh;
		pdsnp->asCapable = target->asCapable;
		datalen = sizeof(*pdsnp);
		respond = 1;
		break;
	}
	if (respond) {
		if (datalen % 2) {
			tlv->data[datalen] = 0;
			datalen++;
		}
		tlv->length = sizeof(tlv->id) + datalen;
		pdulen = rsp->header.messageLength + sizeof(*tlv) + datalen;
		rsp->header.messageLength = pdulen;
		rsp->tlv_count = 1;
		err = msg_pre_send(rsp);
		if (err) {
			goto out;
		}
		err = port_forward(ingress, rsp, pdulen);
	}
out:
	msg_put(rsp);
	return respond ? 1 : 0;
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
	case PORT_DATA_SET_NP:
		pdsnp = (struct port_ds_np *) tlv->data;
		target->neighborPropDelayThresh = pdsnp->neighborPropDelayThresh;
		respond = 1;
		break;
	}
	if (respond && !port_management_get_response(target, ingress, id, req))
		pr_err("port %hu: failed to send management set response", portnum(target));
	return respond ? 1 : 0;
}

static void port_nrate_calculate(struct port *p, tmv_t t3, tmv_t t4, tmv_t c)
{
	tmv_t origin2;
	struct nrate_estimator *n = &p->nrate;

	/*
	 * We experienced a successful exchanges of peer delay request
	 * and response, reset pdr_missing for this port.
	 */
	p->pdr_missing = 0;

	if (!n->ingress1) {
		n->ingress1 = t4;
		n->origin1 = tmv_add(t3, c);
		return;
	}
	n->count++;
	if (n->count < n->max_count) {
		return;
	}
	origin2 = tmv_add(t3, c);
	if (tmv_eq(t4, n->ingress1)) {
		pr_warning("bad timestamps in nrate calculation");
		return;
	}
	n->ratio =
		tmv_dbl(tmv_sub(origin2, n->origin1)) /
		tmv_dbl(tmv_sub(t4, n->ingress1));
	n->ingress1 = t4;
	n->origin1 = origin2;
	n->count = 0;
	n->ratio_valid = 1;
}

static void port_nrate_initialize(struct port *p)
{
	int shift = p->pod.freq_est_interval - p->logMinPdelayReqInterval;

	if (shift < 0)
		shift = 0;
	else if (shift >= sizeof(int) * 8) {
		shift = sizeof(int) * 8 - 1;
		pr_warning("freq_est_interval is too long");
	}

	/* We start in the 'incapable' state. */
	p->pdr_missing = ALLOWED_LOST_RESPONSES + 1;
	p->asCapable = 0;

	p->peer_portid_valid = 0;

	p->nrate.origin1 = tmv_zero();
	p->nrate.ingress1 = tmv_zero();
	p->nrate.max_count = (1 << shift);
	p->nrate.count = 0;
	p->nrate.ratio = 1.0;
	p->nrate.ratio_valid = 0;
}

static int port_set_announce_tmo(struct port *p)
{
	return set_tmo_random(p->fda.fd[FD_ANNOUNCE_TIMER],
			      p->announceReceiptTimeout,
			      p->pod.announce_span, p->logAnnounceInterval);
}

static int port_set_delay_tmo(struct port *p)
{
	if (p->delayMechanism == DM_P2P) {
		return set_tmo_log(p->fda.fd[FD_DELAY_TIMER], 1,
			       p->logMinPdelayReqInterval);
	} else {
		return set_tmo_random(p->fda.fd[FD_DELAY_TIMER], 0, 2,
				p->logMinDelayReqInterval);
	}
}

static int port_set_manno_tmo(struct port *p)
{
	return set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, p->logAnnounceInterval);
}

static int port_set_qualification_tmo(struct port *p)
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

static void port_show_transition(struct port *p,
				 enum port_state next, enum fsm_event event)
{
	if (event == EV_FAULT_DETECTED) {
		pr_notice("port %hu: %s to %s on %s (%s)", portnum(p),
			  ps_str[p->state], ps_str[next], ev_str[event],
			  ft_str(last_fault_type(p)));
	} else {
		pr_notice("port %hu: %s to %s on %s", portnum(p),
			  ps_str[p->state], ps_str[next], ev_str[event]);
	}
}

static void port_slave_priority_warning(struct port *p)
{
	UInteger16 n = portnum(p);
	pr_warning("port %hu: master state recommended in slave only mode", n);
	pr_warning("port %hu: defaultDS.priority1 probably misconfigured", n);
}

static void port_synchronize(struct port *p,
			     struct timespec ingress_ts,
			     struct timestamp origin_ts,
			     Integer64 correction1, Integer64 correction2)
{
	enum servo_state state;

	port_set_sync_rx_tmo(p);

	state = clock_synchronize(p->clock, ingress_ts, origin_ts,
				  correction1, correction2);
	switch (state) {
	case SERVO_UNLOCKED:
		port_dispatch(p, EV_SYNCHRONIZATION_FAULT, 0);
		break;
	case SERVO_JUMP:
		port_dispatch(p, EV_SYNCHRONIZATION_FAULT, 0);
		if (p->delay_req) {
			msg_put(p->delay_req);
			p->delay_req = NULL;
		}
		if (p->peer_delay_req) {
			msg_put(p->peer_delay_req);
			p->peer_delay_req = NULL;
		}
		break;
	case SERVO_LOCKED:
		port_dispatch(p, EV_MASTER_CLOCK_SELECTED, 0);
		break;
	}
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
			msg_put(p->last_syncfup);
			msg_get(m);
			p->last_syncfup = m;
			break;
		case SYNC_MATCH:
			break;
		case FUP_MISMATCH:
			msg_put(p->last_syncfup);
			msg_get(m);
			p->last_syncfup = m;
			p->syfu = SF_HAVE_FUP;
			break;
		case FUP_MATCH:
			syn = p->last_syncfup;
			port_synchronize(p, syn->hwts.ts, m->ts.pdu,
					 syn->header.correction,
					 m->header.correction);
			msg_put(p->last_syncfup);
			p->syfu = SF_EMPTY;
			break;
		}
		break;

	case SF_HAVE_FUP:
		switch (event) {
		case SYNC_MISMATCH:
			msg_put(p->last_syncfup);
			msg_get(m);
			p->last_syncfup = m;
			p->syfu = SF_HAVE_SYNC;
			break;
		case SYNC_MATCH:
			fup = p->last_syncfup;
			port_synchronize(p, m->hwts.ts, fup->ts.pdu,
					 m->header.correction,
					 fup->header.correction);
			msg_put(p->last_syncfup);
			p->syfu = SF_EMPTY;
			break;
		case FUP_MISMATCH:
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
	int cnt, pdulen;

	/* If multiple pdelay resp were not detected the counter can be reset */
	if (!p->multiple_pdr_detected)
		p->multiple_seq_pdr_count = 0;
	p->multiple_pdr_detected = 0;

	msg = msg_allocate();
	if (!msg)
		return -1;

	pdulen = sizeof(struct pdelay_req_msg);
	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = PDELAY_REQ | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.correction         = -p->pod.asymmetry;
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.delayreq++;
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = port_is_ieee8021as(p) ?
		p->logMinPdelayReqInterval : 0x7f;

	if (msg_pre_send(msg))
		goto out;

	cnt = transport_peer(p->trp, &p->fda, 1, msg, pdulen, &msg->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: send peer delay request failed", portnum(p));
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

static int port_delay_request(struct port *p)
{
	struct ptp_message *msg;
	int cnt, pdulen;

	/* Time to send a new request, forget current pdelay resp and fup */
	if (p->peer_delay_resp) {
		msg_put(p->peer_delay_resp);
		p->peer_delay_resp = NULL;
	}
	if (p->peer_delay_fup) {
		msg_put(p->peer_delay_fup);
		p->peer_delay_fup = NULL;
	}

	if (p->delayMechanism == DM_P2P)
		return port_pdelay_request(p);

	msg = msg_allocate();
	if (!msg)
		return -1;

	pdulen = sizeof(struct delay_req_msg);
	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = DELAY_REQ | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.correction         = -p->pod.asymmetry;
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.delayreq++;
	msg->header.control            = CTL_DELAY_REQ;
	msg->header.logMessageInterval = 0x7f;

	if (msg_pre_send(msg))
		goto out;

	cnt = transport_send(p->trp, &p->fda, 1, msg, pdulen, &msg->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: send delay request failed", portnum(p));
		goto out;
	}
	if (msg_sots_missing(msg)) {
		pr_err("missing timestamp on transmitted delay request");
		goto out;
	}

	if (p->delay_req)
		msg_put(p->delay_req);

	p->delay_req = msg;
	return 0;
out:
	msg_put(msg);
	return -1;
}

static int port_tx_announce(struct port *p)
{
	struct parent_ds *dad = clock_parent_ds(p->clock);
	struct timePropertiesDS *tp = clock_time_properties(p->clock);
	struct ptp_message *msg;
	int cnt, err = 0, pdulen;

	if (!port_capable(p)) {
		return 0;
	}
	msg = msg_allocate();
	if (!msg)
		return -1;

	pdulen = sizeof(struct announce_msg);
	msg->hwts.type = p->timestamping;

	if (p->pod.path_trace_enabled)
		pdulen += path_trace_append(p, msg, dad);

	msg->header.tsmt               = ANNOUNCE | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.announce++;
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = p->logAnnounceInterval;

	msg->header.flagField[1] = tp->flags;

	msg->announce.currentUtcOffset        = tp->currentUtcOffset;
	msg->announce.grandmasterPriority1    = dad->pds.grandmasterPriority1;
	msg->announce.grandmasterClockQuality = dad->pds.grandmasterClockQuality;
	msg->announce.grandmasterPriority2    = dad->pds.grandmasterPriority2;
	msg->announce.grandmasterIdentity     = dad->pds.grandmasterIdentity;
	msg->announce.stepsRemoved            = clock_steps_removed(p->clock);
	msg->announce.timeSource              = tp->timeSource;

	if (msg_pre_send(msg)) {
		err = -1;
		goto out;
	}
	cnt = transport_send(p->trp, &p->fda, 0, msg, pdulen, &msg->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: send announce failed", portnum(p));
		err = -1;
	}
out:
	msg_put(msg);
	return err;
}

static int port_tx_sync(struct port *p)
{
	struct ptp_message *msg, *fup;
	int cnt, err = 0, pdulen;
	int event = p->timestamping == TS_ONESTEP ? TRANS_ONESTEP : TRANS_EVENT;

	if (!port_capable(p)) {
		return 0;
	}
	if (port_sync_incapable(p)) {
		return 0;
	}
	msg = msg_allocate();
	if (!msg)
		return -1;
	fup = msg_allocate();
	if (!fup) {
		msg_put(msg);
		return -1;
	}

	pdulen = sizeof(struct sync_msg);
	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = SYNC | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = p->seqnum.sync++;
	msg->header.control            = CTL_SYNC;
	msg->header.logMessageInterval = p->logSyncInterval;

	if (p->timestamping != TS_ONESTEP)
		msg->header.flagField[0] |= TWO_STEP;

	if (msg_pre_send(msg)) {
		err = -1;
		goto out;
	}
	cnt = transport_send(p->trp, &p->fda, event, msg, pdulen, &msg->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: send sync failed", portnum(p));
		err = -1;
		goto out;
	}
	if (p->timestamping == TS_ONESTEP) {
		goto out;
	} else if (msg_sots_missing(msg)) {
		pr_err("missing timestamp on transmitted sync");
		err = -1;
		goto out;
	}

	/*
	 * Send the follow up message right away.
	 */
	pdulen = sizeof(struct follow_up_msg);
	fup->hwts.type = p->timestamping;

	if (p->pod.follow_up_info)
		pdulen += follow_up_info_append(p, fup);

	fup->header.tsmt               = FOLLOW_UP | p->transportSpecific;
	fup->header.ver                = PTP_VERSION;
	fup->header.messageLength      = pdulen;
	fup->header.domainNumber       = clock_domain_number(p->clock);
	fup->header.sourcePortIdentity = p->portIdentity;
	fup->header.sequenceId         = p->seqnum.sync - 1;
	fup->header.control            = CTL_FOLLOW_UP;
	fup->header.logMessageInterval = p->logSyncInterval;

	ts_to_timestamp(&msg->hwts.ts, &fup->follow_up.preciseOriginTimestamp);

	if (msg_pre_send(fup)) {
		err = -1;
		goto out;
	}
	cnt = transport_send(p->trp, &p->fda, 0, fup, pdulen, &fup->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: send follow up failed", portnum(p));
		err = -1;
	}
out:
	msg_put(msg);
	msg_put(fup);
	return err;
}

/*
 * port initialize and disable
 */
static int port_is_enabled(struct port *p)
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

static void flush_last_sync(struct port *p)
{
	if (p->syfu != SF_EMPTY) {
		msg_put(p->last_syncfup);
		p->syfu = SF_EMPTY;
	}
}

static void flush_delay_req(struct port *p)
{
	if (p->delay_req) {
		msg_put(p->delay_req);
		p->delay_req = NULL;
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

static void port_disable(struct port *p)
{
	int i;

	flush_last_sync(p);
	flush_delay_req(p);
	flush_peer_delay(p);

	p->best = NULL;
	free_foreign_masters(p);
	clock_remove_fda(p->clock, p, p->fda);
	transport_close(p->trp, &p->fda);

	for (i = 0; i < N_TIMER_FDS; i++) {
		close(p->fda.fd[FD_ANNOUNCE_TIMER + i]);
	}
}

static int port_initialize(struct port *p)
{
	int fd[N_TIMER_FDS], i;

	p->multiple_seq_pdr_count  = 0;
	p->multiple_pdr_detected   = 0;
	p->last_fault_type         = FT_UNSPECIFIED;
	p->logMinDelayReqInterval  = p->pod.logMinDelayReqInterval;
	p->peerMeanPathDelay       = 0;
	p->logAnnounceInterval     = p->pod.logAnnounceInterval;
	p->announceReceiptTimeout  = p->pod.announceReceiptTimeout;
	p->syncReceiptTimeout      = p->pod.syncReceiptTimeout;
	p->transportSpecific       = p->pod.transportSpecific;
	p->logSyncInterval         = p->pod.logSyncInterval;
	p->logMinPdelayReqInterval = p->pod.logMinPdelayReqInterval;
	p->neighborPropDelayThresh = p->pod.neighborPropDelayThresh;
	p->min_neighbor_prop_delay = p->pod.min_neighbor_prop_delay;

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
	if (transport_open(p->trp, p->name, &p->fda, p->timestamping))
		goto no_tropen;

	for (i = 0; i < N_TIMER_FDS; i++) {
		p->fda.fd[FD_ANNOUNCE_TIMER + i] = fd[i];
	}

	if (port_set_announce_tmo(p))
		goto no_tmo;

	port_nrate_initialize(p);

	clock_install_fda(p->clock, p, p->fda);
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
	if (!port_is_enabled(p)) {
		return 0;
	}
	clock_remove_fda(p->clock, p, p->fda);
	transport_close(p->trp, &p->fda);
	if (transport_open(p->trp, p->name, &p->fda, p->timestamping)) {
		return -1;
	}
	clock_install_fda(p->clock, p, p->fda);
	return 0;
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
	if (p->pod.path_trace_enabled) {
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
static int process_announce(struct port *p, struct ptp_message *m)
{
	int result = 0;

	/* Do not qualify announce messages with stepsRemoved >= 255, see
	 * IEEE1588-2008 section 9.3.2.5 (d)
	 */
	if (m->announce.stepsRemoved >= 255)
		return result;

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
	struct ptp_message *msg;
	int cnt, err = 0, pdulen;

	if (p->state != PS_MASTER && p->state != PS_GRAND_MASTER)
		return 0;

	if (p->delayMechanism == DM_P2P) {
		pr_warning("port %hu: delay request on P2P port", portnum(p));
		return 0;
	}

	msg = msg_allocate();
	if (!msg)
		return -1;

	pdulen = sizeof(struct delay_resp_msg);
	msg->hwts.type = p->timestamping;

	msg->header.tsmt               = DELAY_RESP | p->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = m->header.domainNumber;
	msg->header.correction         = m->header.correction;
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId         = m->header.sequenceId;
	msg->header.control            = CTL_DELAY_RESP;
	msg->header.logMessageInterval = p->logMinDelayReqInterval;

	ts_to_timestamp(&m->hwts.ts, &msg->delay_resp.receiveTimestamp);

	msg->delay_resp.requestingPortIdentity = m->header.sourcePortIdentity;

	if (msg_pre_send(msg)) {
		err = -1;
		goto out;
	}
	cnt = transport_send(p->trp, &p->fda, 0, msg, pdulen, NULL);
	if (cnt <= 0) {
		pr_err("port %hu: send delay response failed", portnum(p));
		err = -1;
	}
out:
	msg_put(msg);
	return err;
}

static void process_delay_resp(struct port *p, struct ptp_message *m)
{
	struct delay_req_msg *req;
	struct delay_resp_msg *rsp = &m->delay_resp;
	struct PortIdentity master;

	if (!p->delay_req)
		return;

	master = clock_parent_identity(p->clock);
	req = &p->delay_req->delay_req;

	if (p->state != PS_UNCALIBRATED && p->state != PS_SLAVE)
		return;
	if (!pid_eq(&rsp->requestingPortIdentity, &req->hdr.sourcePortIdentity))
		return;
	if (rsp->hdr.sequenceId != ntohs(req->hdr.sequenceId))
		return;
	if (!pid_eq(&master, &m->header.sourcePortIdentity))
		return;

	clock_path_delay(p->clock, p->delay_req->hwts.ts, m->ts.pdu,
			 m->header.correction);

	if (p->logMinDelayReqInterval != rsp->hdr.logMessageInterval) {
		// TODO - validate the input.
		p->logMinDelayReqInterval = rsp->hdr.logMessageInterval;
		pr_notice("port %hu: minimum delay request interval 2^%d",
			portnum(p), p->logMinDelayReqInterval);
	}
}

static void process_follow_up(struct port *p, struct ptp_message *m)
{
	enum syfu_event event;
	struct PortIdentity master;
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
	master = clock_parent_identity(p->clock);
	if (memcmp(&master, &m->header.sourcePortIdentity, sizeof(master)))
		return;

	if (p->pod.follow_up_info) {
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

static int process_pdelay_req(struct port *p, struct ptp_message *m)
{
	struct ptp_message *rsp, *fup;
	int cnt, err = -1, rsp_len, fup_len;

	if (p->delayMechanism == DM_E2E) {
		pr_warning("port %hu: pdelay_req on E2E port", portnum(p));
		return 0;
	}
	if (p->delayMechanism == DM_AUTO) {
		pr_info("port %hu: peer detected, switch to P2P", portnum(p));
		p->delayMechanism = DM_P2P;
		port_set_delay_tmo(p);
	}
	if (p->peer_portid_valid) {
		if (!pid_eq(&p->peer_portid, &m->header.sourcePortIdentity)) {
			pr_err("port %hu: received pdelay_req msg with "
				"unexpected peer port id %s",
				portnum(p),
				pid2str(&m->header.sourcePortIdentity));
			p->peer_portid_valid = 0;
			port_capable(p);
		}
	} else {
		p->peer_portid_valid = 1;
		p->peer_portid = m->header.sourcePortIdentity;
		pr_debug("port %hu: peer port id set to %s", portnum(p),
			pid2str(&p->peer_portid));
	}

	rsp = msg_allocate();
	if (!rsp)
		return -1;
	fup = msg_allocate();
	if (!fup) {
		msg_put(rsp);
		return -1;
	}

	rsp_len = sizeof(struct pdelay_resp_msg);
	rsp->hwts.type = p->timestamping;

	rsp->header.tsmt               = PDELAY_RESP | p->transportSpecific;
	rsp->header.ver                = PTP_VERSION;
	rsp->header.messageLength      = rsp_len;
	rsp->header.domainNumber       = m->header.domainNumber;
	rsp->header.sourcePortIdentity = p->portIdentity;
	rsp->header.sequenceId         = m->header.sequenceId;
	rsp->header.control            = CTL_OTHER;
	rsp->header.logMessageInterval = 0x7f;
	/*
	 * NB - There is no kernel support for one step P2P messaging,
	 * so we always send a follow up message.
	 */
	rsp->header.flagField[0] |= TWO_STEP;

	/*
	 * NB - We do not have any fraction nanoseconds for the correction
	 * fields, neither in the response or the follow up.
	 */
	ts_to_timestamp(&m->hwts.ts, &rsp->pdelay_resp.requestReceiptTimestamp);
	rsp->pdelay_resp.requestingPortIdentity = m->header.sourcePortIdentity;

	fup_len = sizeof(struct pdelay_resp_fup_msg);
	fup->hwts.type = p->timestamping;

	fup->header.tsmt               = PDELAY_RESP_FOLLOW_UP | p->transportSpecific;
	fup->header.ver                = PTP_VERSION;
	fup->header.messageLength      = fup_len;
	fup->header.domainNumber       = m->header.domainNumber;
	fup->header.correction         = m->header.correction;
	fup->header.sourcePortIdentity = p->portIdentity;
	fup->header.sequenceId         = m->header.sequenceId;
	fup->header.control            = CTL_OTHER;
	fup->header.logMessageInterval = 0x7f;

	fup->pdelay_resp_fup.requestingPortIdentity = m->header.sourcePortIdentity;

	if (msg_pre_send(rsp))
		goto out;

	cnt = transport_peer(p->trp, &p->fda, 1, rsp, rsp_len, &rsp->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: send peer delay response failed", portnum(p));
		goto out;
	}
	if (msg_sots_missing(rsp)) {
		pr_err("missing timestamp on transmitted peer delay response");
		goto out;
	}

	ts_to_timestamp(&rsp->hwts.ts,
			&fup->pdelay_resp_fup.responseOriginTimestamp);

	if (msg_pre_send(fup))
		goto out;

	cnt = transport_peer(p->trp, &p->fda, 0, fup, fup_len, &rsp->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: send pdelay_resp_fup failed", portnum(p));
		goto out;
	}
	err = 0;
out:
	msg_put(rsp);
	msg_put(fup);
	return err;
}

static void port_peer_delay(struct port *p)
{
	tmv_t c1, c2, t1, t2, t3, t4, pd;
	struct ptp_message *req = p->peer_delay_req;
	struct ptp_message *rsp = p->peer_delay_resp;
	struct ptp_message *fup = p->peer_delay_fup;
	double adj_t41;

	/* Check for response, validate port and sequence number. */

	if (!rsp)
		return;

	if (!pid_eq(&rsp->pdelay_resp.requestingPortIdentity, &p->portIdentity))
		return;

	if (rsp->header.sequenceId != ntohs(req->header.sequenceId))
		return;

	t1 = timespec_to_tmv(req->hwts.ts);
	t4 = timespec_to_tmv(rsp->hwts.ts);
	c1 = correction_to_tmv(rsp->header.correction + p->pod.asymmetry);

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
	adj_t41 = p->nrate.ratio * clock_rate_ratio(p->clock) *
			tmv_dbl(tmv_sub(t4, t1));
	pd = tmv_sub(dbl_tmv(adj_t41), tmv_sub(t3, t2));
	pd = tmv_sub(pd, c1);
	pd = tmv_sub(pd, c2);
	pd = tmv_div(pd, 2);

	p->peer_delay = filter_sample(p->delay_filter, pd);

	p->peerMeanPathDelay = tmv_to_TimeInterval(p->peer_delay);

	pr_debug("pdelay %hu   %10" PRId64 "%10" PRId64, portnum(p), p->peer_delay, pd);

	if (p->pod.follow_up_info)
		port_nrate_calculate(p, t3, t4, tmv_add(c1, c2));

	if (p->state == PS_UNCALIBRATED || p->state == PS_SLAVE) {
		clock_peer_delay(p->clock, p->peer_delay, p->nrate.ratio);
	}

	msg_put(p->peer_delay_req);
	p->peer_delay_req = NULL;
}

static int process_pdelay_resp(struct port *p, struct ptp_message *m)
{
	if (p->peer_delay_resp) {
		if (!source_pid_eq(p->peer_delay_resp, m)) {
			pr_err("port %hu: multiple peer responses", portnum(p));
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
		pr_err("port %hu: rogue peer delay response", portnum(p));
		return -1;
	}
	if (p->peer_portid_valid) {
		if (!pid_eq(&p->peer_portid, &m->header.sourcePortIdentity)) {
			pr_err("port %hu: received pdelay_resp msg with "
				"unexpected peer port id %s",
				portnum(p),
				pid2str(&m->header.sourcePortIdentity));
			p->peer_portid_valid = 0;
			port_capable(p);
		}
	} else {
		p->peer_portid_valid = 1;
		p->peer_portid = m->header.sourcePortIdentity;
		pr_debug("port %hu: peer port id set to %s", portnum(p),
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

static void process_pdelay_resp_fup(struct port *p, struct ptp_message *m)
{
	if (!p->peer_delay_req)
		return;

	if (p->peer_delay_fup)
		msg_put(p->peer_delay_fup);

	msg_get(m);
	p->peer_delay_fup = m;
	port_peer_delay(p);
}

static void process_sync(struct port *p, struct ptp_message *m)
{
	enum syfu_event event;
	struct PortIdentity master;
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
	master = clock_parent_identity(p->clock);
	if (memcmp(&master, &m->header.sourcePortIdentity, sizeof(master))) {
		return;
	}

	if (m->header.logMessageInterval != p->log_sync_interval) {
		p->log_sync_interval = m->header.logMessageInterval;
		clock_sync_interval(p->clock, p->log_sync_interval);
	}

	m->header.correction += p->pod.asymmetry;

	if (one_step(m)) {
		port_synchronize(p, m->hwts.ts, m->ts.pdu,
				 m->header.correction, 0);
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
	transport_destroy(p->trp);
	filter_destroy(p->delay_filter);
	free(p);
}

struct foreign_clock *port_compute_best(struct port *p)
{
	struct foreign_clock *fc;
	struct ptp_message *tmp;

	p->best = NULL;

	LIST_FOREACH(fc, &p->foreign_masters, list) {
		tmp = TAILQ_FIRST(&fc->messages);
		if (!tmp)
			continue;

		announce_to_dataset(tmp, p->clock, &fc->dataset);

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
		set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, -10); /*~1ms*/
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
		set_tmo_log(p->fda.fd[FD_MANNO_TIMER], 1, -10); /*~1ms*/
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

int port_dispatch(struct port *p, enum fsm_event event, int mdiff)
{
	enum port_state next;
	struct fault_interval i;
	int fri_asap = 0;

	if (clock_slave_only(p->clock)) {
		if (event == EV_RS_MASTER || event == EV_RS_GRAND_MASTER) {
			port_slave_priority_warning(p);
		}
		next = ptp_slave_fsm(p->state, event, mdiff);
	} else {
		next = ptp_fsm(p->state, event, mdiff);
	}

	if (!fault_interval(p, last_fault_type(p), &i) &&
	    ((i.val == FRI_ASAP && i.type == FTMO_LOG2_SECONDS) ||
	     (i.val == 0 && i.type == FTMO_LINEAR_SECONDS)))
		fri_asap = 1;
	if (PS_INITIALIZING == next || (PS_FAULTY == next && fri_asap)) {
		/*
		 * This is a special case. Since we initialize the
		 * port immediately, we can skip right to listening
		 * state if all goes well.
		 */
		if (port_is_enabled(p)) {
			port_disable(p);
		}
		next = port_initialize(p) ? PS_FAULTY : PS_LISTENING;
		port_show_transition(p, next, event);
		p->state = next;
		if (next == PS_LISTENING && p->delayMechanism == DM_P2P) {
			port_set_delay_tmo(p);
		}
		return 1;
	}

	if (next == p->state)
		return 0;

	port_show_transition(p, next, event);

	if (p->delayMechanism == DM_P2P) {
		port_p2p_transition(p, next);
	} else {
		port_e2e_transition(p, next);
	}

	p->state = next;
	return 0;
}

enum fsm_event port_event(struct port *p, int fd_index)
{
	enum fsm_event event = EV_NONE;
	struct ptp_message *msg;
	int cnt, fd = p->fda.fd[fd_index], err;

	switch (fd_index) {
	case FD_ANNOUNCE_TIMER:
	case FD_SYNC_RX_TIMER:
		pr_debug("port %hu: %s timeout", portnum(p),
			 fd_index == FD_SYNC_RX_TIMER ? "rx sync" : "announce");
		if (p->best)
			fc_clear(p->best);
		port_set_announce_tmo(p);
		if (clock_slave_only(p->clock) && p->delayMechanism != DM_P2P &&
		    port_renew_transport(p)) {
			return EV_FAULT_DETECTED;
		}
		return EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES;

	case FD_DELAY_TIMER:
		pr_debug("port %hu: delay timeout", portnum(p));
		port_set_delay_tmo(p);
		return port_delay_request(p) ? EV_FAULT_DETECTED : EV_NONE;

	case FD_QUALIFICATION_TIMER:
		pr_debug("port %hu: qualification timeout", portnum(p));
		return EV_QUALIFICATION_TIMEOUT_EXPIRES;

	case FD_MANNO_TIMER:
		pr_debug("port %hu: master tx announce timeout", portnum(p));
		port_set_manno_tmo(p);
		return port_tx_announce(p) ? EV_FAULT_DETECTED : EV_NONE;

	case FD_SYNC_TX_TIMER:
		pr_debug("port %hu: master sync timeout", portnum(p));
		port_set_sync_tx_tmo(p);
		return port_tx_sync(p) ? EV_FAULT_DETECTED : EV_NONE;
	}

	msg = msg_allocate();
	if (!msg)
		return EV_FAULT_DETECTED;

	msg->hwts.type = p->timestamping;

	cnt = transport_recv(p->trp, fd, msg, sizeof(msg->data), &msg->hwts);
	if (cnt <= 0) {
		pr_err("port %hu: recv message failed", portnum(p));
		msg_put(msg);
		return EV_FAULT_DETECTED;
	}
	err = msg_post_recv(msg, cnt);
	if (err) {
		switch (err) {
		case -EBADMSG:
			pr_err("port %hu: bad message", portnum(p));
			break;
		case -ETIME:
			pr_err("port %hu: received %s without timestamp",
				portnum(p), msg_type_string(msg_type(msg)));
			break;
		case -EPROTO:
			pr_debug("port %hu: ignoring message", portnum(p));
		}
		msg_put(msg);
		return EV_NONE;
	}
	if (msg->hwts.ts.tv_sec && msg->hwts.ts.tv_nsec) {
		clock_check_ts(p->clock, msg->hwts.ts);
	}
	if (port_ignore(p, msg)) {
		msg_put(msg);
		return EV_NONE;
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
		break;
	case MANAGEMENT:
		if (clock_manage(p->clock, p, msg))
			event = EV_STATE_DECISION_EVENT;
		break;
	}

	msg_put(msg);
	return event;
}

int port_forward(struct port *p, struct ptp_message *msg, int msglen)
{
	int cnt;
	cnt = transport_send(p->trp, &p->fda, 0, msg, msglen, &msg->hwts);
	return cnt <= 0 ? -1 : 0;
}

struct PortIdentity port_identity(struct port *p)
{
	return p->portIdentity;
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
			return 0;
		break;
	case SET:
		if (port_management_set(p, ingress, mgt->id, msg))
			return 0;
		break;
	case COMMAND:
		break;
	default:
		return -1;
	}

	switch (mgt->id) {
	case NULL_MANAGEMENT:
	case CLOCK_DESCRIPTION:
	case PORT_DATA_SET:
	case LOG_ANNOUNCE_INTERVAL:
	case ANNOUNCE_RECEIPT_TIMEOUT:
	case LOG_SYNC_INTERVAL:
	case VERSION_NUMBER:
	case ENABLE_PORT:
	case DISABLE_PORT:
	case UNICAST_NEGOTIATION_ENABLE:
	case UNICAST_MASTER_TABLE:
	case UNICAST_MASTER_MAX_TABLE_SIZE:
	case ACCEPTABLE_MASTER_TABLE_ENABLED:
	case ALTERNATE_MASTER:
	case TRANSPARENT_CLOCK_PORT_DATA_SET:
	case DELAY_MECHANISM:
	case LOG_MIN_PDELAY_REQ_INTERVAL:
		port_management_send_error(p, ingress, msg, NOT_SUPPORTED);
		break;
	default:
		port_management_send_error(p, ingress, msg, NO_SUCH_ID);
		return -1;
	}
	return 0;
}

int port_management_error(struct PortIdentity pid, struct port *ingress,
			  struct ptp_message *req, Enumeration16 error_id)
{
	struct ptp_message *msg;
	struct management_tlv *mgt;
	struct management_error_status *mes;
	int err = 0, pdulen;

	msg = port_management_reply(pid, ingress, req);
	if (!msg) {
		return -1;
	}
	mgt = (struct management_tlv *) req->management.suffix;
	mes = (struct management_error_status *) msg->management.suffix;
	mes->type = TLV_MANAGEMENT_ERROR_STATUS;
	mes->length = 8;
	mes->error = error_id;
	mes->id = mgt->id;
	pdulen = msg->header.messageLength + sizeof(*mes);
	msg->header.messageLength = pdulen;
	msg->tlv_count = 1;

	err = msg_pre_send(msg);
	if (err) {
		goto out;
	}
	err = port_forward(ingress, msg, pdulen);
out:
	msg_put(msg);
	return err;
}

struct ptp_message *port_management_reply(struct PortIdentity pid,
					  struct port *ingress,
					  struct ptp_message *req)
{
	struct ptp_message *msg;
	int pdulen;

	msg = msg_allocate();
	if (!msg)
		return NULL;

	pdulen = sizeof(struct management_msg);
	msg->hwts.type = ingress->timestamping;

	msg->header.tsmt               = MANAGEMENT | ingress->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = clock_domain_number(ingress->clock);
	msg->header.sourcePortIdentity = pid;
	msg->header.sequenceId         = req->header.sequenceId;
	msg->header.control            = CTL_MANAGEMENT;
	msg->header.logMessageInterval = 0x7f;

	msg->management.targetPortIdentity = req->header.sourcePortIdentity;
	msg->management.startingBoundaryHops =
		req->management.startingBoundaryHops - req->management.boundaryHops;
	msg->management.boundaryHops = msg->management.startingBoundaryHops;

	switch (management_action(req)) {
	case GET: case SET:
		msg->management.flags = RESPONSE;
		break;
	case COMMAND:
		msg->management.flags = ACKNOWLEDGE;
		break;
	}
	return msg;
}

struct port *port_open(int phc_index,
		       enum timestamp_type timestamping,
		       int number,
		       struct interface *interface,
		       struct clock *clock)
{
	struct port *p = malloc(sizeof(*p));

	if (!p)
		return NULL;

	memset(p, 0, sizeof(*p));

	if (interface->transport == TRANS_UDS)
		; /* UDS cannot have a PHC. */
	else if (!interface->ts_info.valid)
		pr_warning("port %d: get_ts_info not supported", number);
	else if (phc_index >= 0 && phc_index != interface->ts_info.phc_index) {
		pr_err("port %d: PHC device mismatch", number);
		pr_err("port %d: /dev/ptp%d requested, but /dev/ptp%d attached",
		       number, phc_index, interface->ts_info.phc_index);
		free(p);
		return NULL;
	}

	p->pod = interface->pod;
	p->name = interface->name;
	p->clock = clock;
	p->trp = transport_create(interface->transport);
	if (!p->trp) {
		free(p);
		return NULL;
	}
	p->timestamping = timestamping;
	p->portIdentity.clockIdentity = clock_identity(clock);
	p->portIdentity.portNumber = number;
	p->state = PS_INITIALIZING;
	p->delayMechanism = interface->dm;
	p->versionNumber = PTP_VERSION;

	p->delay_filter = filter_create(interface->delay_filter,
					interface->delay_filter_length);
	if (!p->delay_filter) {
		pr_err("Failed to create delay filter");
		transport_destroy(p->trp);
		free(p);
		return NULL;
	}
	p->nrate.ratio = 1.0;
	return p;
}

enum port_state port_state(struct port *port)
{
	return port->state;
}
