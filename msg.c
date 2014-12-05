/**
 * @file msg.c
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
#include <string.h>
#include <time.h>

#include <asm/byteorder.h>

#include "contain.h"
#include "msg.h"
#include "print.h"
#include "tlv.h"

#define VERSION_MASK 0x0f
#define VERSION      0x02

/*
 * Head room fits a VLAN Ethernet header, and 'msg' is 64 bit aligned.
 */
#define MSG_HEADROOM 24

struct message_storage {
	unsigned char reserved[MSG_HEADROOM];
	struct ptp_message msg;
} PACKED;

static TAILQ_HEAD(msg_pool, ptp_message) msg_pool;

static struct {
	int total;
	int count;
} pool_stats;

#ifdef DEBUG_POOL
static void pool_debug(const char *str, void *addr)
{
	fprintf(stderr, "*** %p %10s total %d count %d used %d\n",
		addr, str, pool_stats.total, pool_stats.count,
		pool_stats.total - pool_stats.count);
}
#else
static void pool_debug(const char *str, void *addr)
{
}
#endif

static void announce_pre_send(struct announce_msg *m)
{
	m->currentUtcOffset = htons(m->currentUtcOffset);
	m->grandmasterClockQuality.offsetScaledLogVariance =
		htons(m->grandmasterClockQuality.offsetScaledLogVariance);
	m->stepsRemoved = htons(m->stepsRemoved);
}

static void announce_post_recv(struct announce_msg *m)
{
	m->currentUtcOffset = ntohs(m->currentUtcOffset);
	m->grandmasterClockQuality.offsetScaledLogVariance =
		ntohs(m->grandmasterClockQuality.offsetScaledLogVariance);
	m->stepsRemoved = ntohs(m->stepsRemoved);
}

int64_t host2net64(int64_t val)
{
	return __cpu_to_be64(val);
}

int64_t net2host64(int64_t val)
{
	return __be64_to_cpu(val);
}

static int hdr_post_recv(struct ptp_header *m)
{
	if ((m->ver & VERSION_MASK) != VERSION)
		return -EPROTO;
	m->messageLength = ntohs(m->messageLength);
	m->correction = net2host64(m->correction);
	m->sourcePortIdentity.portNumber = ntohs(m->sourcePortIdentity.portNumber);
	m->sequenceId = ntohs(m->sequenceId);
	return 0;
}

static int hdr_pre_send(struct ptp_header *m)
{
	m->messageLength = htons(m->messageLength);
	m->correction = host2net64(m->correction);
	m->sourcePortIdentity.portNumber = htons(m->sourcePortIdentity.portNumber);
	m->sequenceId = htons(m->sequenceId);
	return 0;
}

static void port_id_post_recv(struct PortIdentity *pid)
{
	pid->portNumber = ntohs(pid->portNumber);
}

static void port_id_pre_send(struct PortIdentity *pid)
{
	pid->portNumber = htons(pid->portNumber);
}

static int suffix_post_recv(uint8_t *ptr, int len, struct tlv_extra *last)
{
	int cnt, err;
	struct TLV *tlv;

	if (!ptr)
		return 0;

	for (cnt = 0; len > sizeof(struct TLV); cnt++) {
		tlv = (struct TLV *) ptr;
		tlv->type = ntohs(tlv->type);
		tlv->length = ntohs(tlv->length);
		if (tlv->length % 2) {
			return -EBADMSG;
		}
		len -= sizeof(struct TLV);
		ptr += sizeof(struct TLV);
		if (tlv->length > len) {
			return -EBADMSG;
		}
		len -= tlv->length;
		ptr += tlv->length;
		err = tlv_post_recv(tlv, len ? NULL : last);
		if (err)
			return err;
	}
	return cnt;
}

static void suffix_pre_send(uint8_t *ptr, int cnt, struct tlv_extra *last)
{
	int i;
	struct TLV *tlv;

	if (!ptr)
		return;

	for (i = 0; i < cnt; i++) {
		tlv = (struct TLV *) ptr;
		tlv_pre_send(tlv, i == cnt - 1 ? last : NULL);
		ptr += sizeof(struct TLV) + tlv->length;
		tlv->type = htons(tlv->type);
		tlv->length = htons(tlv->length);
	}
}

static void timestamp_post_recv(struct ptp_message *m, struct Timestamp *ts)
{
	uint32_t lsb = ntohl(ts->seconds_lsb);
	uint16_t msb = ntohs(ts->seconds_msb);

	m->ts.pdu.sec  = ((uint64_t)lsb) | (((uint64_t)msb) << 32);
	m->ts.pdu.nsec = ntohl(ts->nanoseconds);
}

static void timestamp_pre_send(struct Timestamp *ts)
{
	ts->seconds_lsb = htonl(ts->seconds_lsb);
	ts->seconds_msb = htons(ts->seconds_msb);
	ts->nanoseconds = htonl(ts->nanoseconds);
}

/* public methods */

struct ptp_message *msg_allocate(void)
{
	struct message_storage *s;
	struct ptp_message *m = TAILQ_FIRST(&msg_pool);

	if (m) {
		TAILQ_REMOVE(&msg_pool, m, list);
		pool_stats.count--;
		pool_debug("dequeue", m);
	} else {
		s = malloc(sizeof(*s));
		if (s) {
			m = &s->msg;
			pool_stats.total++;
			pool_debug("allocate", m);
		}
	}
	if (m) {
		memset(m, 0, sizeof(*m));
		m->refcnt = 1;
	}

	return m;
}

void msg_cleanup(void)
{
	struct message_storage *s;
	struct ptp_message *m;
	while ((m = TAILQ_FIRST(&msg_pool)) != NULL) {
		TAILQ_REMOVE(&msg_pool, m, list);
		s = container_of(m, struct message_storage, msg);
		free(s);
	}
}

void msg_get(struct ptp_message *m)
{
	m->refcnt++;
}

int msg_post_recv(struct ptp_message *m, int cnt)
{
	int pdulen, type, err;
	uint8_t *suffix = NULL;

	if (cnt < sizeof(struct ptp_header))
		return -EBADMSG;

	err = hdr_post_recv(&m->header);
	if (err)
		return err;

	type = msg_type(m);

	switch (type) {
	case SYNC:
		pdulen = sizeof(struct sync_msg);
		break;
	case DELAY_REQ:
		pdulen = sizeof(struct delay_req_msg);
		break;
	case PDELAY_REQ:
		pdulen = sizeof(struct pdelay_req_msg);
		break;
	case PDELAY_RESP:
		pdulen = sizeof(struct pdelay_resp_msg);
		break;
	case FOLLOW_UP:
		pdulen = sizeof(struct follow_up_msg);
		break;
	case DELAY_RESP:
		pdulen = sizeof(struct delay_resp_msg);
		break;
	case PDELAY_RESP_FOLLOW_UP:
		pdulen = sizeof(struct pdelay_resp_fup_msg);
		break;
	case ANNOUNCE:
		pdulen = sizeof(struct announce_msg);
		break;
	case SIGNALING:
		pdulen = sizeof(struct signaling_msg);
		break;
	case MANAGEMENT:
		pdulen = sizeof(struct management_msg);
		break;
	default:
		return -EBADMSG;
	}

	if (cnt < pdulen)
		return -EBADMSG;

	switch (type) {
	case SYNC:
		timestamp_post_recv(m, &m->sync.originTimestamp);
		break;
	case DELAY_REQ:
		break;
	case PDELAY_REQ:
		break;
	case PDELAY_RESP:
		timestamp_post_recv(m, &m->pdelay_resp.requestReceiptTimestamp);
		port_id_post_recv(&m->pdelay_resp.requestingPortIdentity);
		break;
	case FOLLOW_UP:
		timestamp_post_recv(m, &m->follow_up.preciseOriginTimestamp);
		suffix = m->follow_up.suffix;
		break;
	case DELAY_RESP:
		timestamp_post_recv(m, &m->delay_resp.receiveTimestamp);
		suffix = m->delay_resp.suffix;
		break;
	case PDELAY_RESP_FOLLOW_UP:
		timestamp_post_recv(m, &m->pdelay_resp_fup.responseOriginTimestamp);
		port_id_post_recv(&m->pdelay_resp_fup.requestingPortIdentity);
		suffix = m->pdelay_resp_fup.suffix;
		break;
	case ANNOUNCE:
		clock_gettime(CLOCK_MONOTONIC, &m->ts.host);
		timestamp_post_recv(m, &m->announce.originTimestamp);
		announce_post_recv(&m->announce);
		suffix = m->announce.suffix;
		break;
	case SIGNALING:
		suffix = m->signaling.suffix;
		break;
	case MANAGEMENT:
		port_id_post_recv(&m->management.targetPortIdentity);
		suffix = m->management.suffix;
		break;
	}

	if (msg_sots_missing(m))
		return -ETIME;

	m->tlv_count = suffix_post_recv(suffix, cnt - pdulen, &m->last_tlv);
	if (m->tlv_count < 0)
		return m->tlv_count;

	return 0;
}

int msg_pre_send(struct ptp_message *m)
{
	int type;
	uint8_t *suffix = NULL;

	if (hdr_pre_send(&m->header))
		return -1;

	type = msg_type(m);

	switch (type) {
	case SYNC:
		break;
	case DELAY_REQ:
		break;
	case PDELAY_REQ:
		break;
	case PDELAY_RESP:
		timestamp_pre_send(&m->pdelay_resp.requestReceiptTimestamp);
		port_id_pre_send(&m->pdelay_resp.requestingPortIdentity);
		break;
	case FOLLOW_UP:
		timestamp_pre_send(&m->follow_up.preciseOriginTimestamp);
		suffix = m->follow_up.suffix;
		break;
	case DELAY_RESP:
		timestamp_pre_send(&m->delay_resp.receiveTimestamp);
		m->delay_resp.requestingPortIdentity.portNumber =
			htons(m->delay_resp.requestingPortIdentity.portNumber);
		suffix = m->delay_resp.suffix;
		break;
	case PDELAY_RESP_FOLLOW_UP:
		timestamp_pre_send(&m->pdelay_resp_fup.responseOriginTimestamp);
		port_id_pre_send(&m->pdelay_resp_fup.requestingPortIdentity);
		suffix = m->pdelay_resp_fup.suffix;
		break;
	case ANNOUNCE:
		announce_pre_send(&m->announce);
		suffix = m->announce.suffix;
		break;
	case SIGNALING:
		suffix = m->signaling.suffix;
		break;
	case MANAGEMENT:
		port_id_pre_send(&m->management.targetPortIdentity);
		suffix = m->management.suffix;
		break;
	default:
		return -1;
	}
	suffix_pre_send(suffix, m->tlv_count, &m->last_tlv);
	return 0;
}

const char *msg_type_string(int type)
{
	switch (type) {
	case SYNC:
		return "SYNC";
	case DELAY_REQ:
		return "DELAY_REQ";
	case PDELAY_REQ:
		return "PDELAY_REQ";
	case PDELAY_RESP:
		return "PDELAY_RESP";
	case FOLLOW_UP:
		return "FOLLOW_UP";
	case DELAY_RESP:
		return "DELAY_RESP";
	case PDELAY_RESP_FOLLOW_UP:
		return "PDELAY_RESP_FOLLOW_UP";
	case ANNOUNCE:
		return "ANNOUNCE";
	case SIGNALING:
		return "SIGNALING";
	case MANAGEMENT:
		return "MANAGEMENT";
	}
	return "unknown";
}

void msg_print(struct ptp_message *m, FILE *fp)
{
	fprintf(fp,
		"\t"
		"%-10s "
//		"versionPTP         0x%02X "
//		"messageLength      %hu "
//		"domainNumber       %u "
//		"reserved1          0x%02X "
//		"flagField          0x%02X%02X "
//		"correction         %lld "
//		"reserved2          %u "
//		"sourcePortIdentity ... "
		"sequenceId %4hu "
//		"control            %u "
//		"logMessageInterval %d "
		,
		msg_type_string(msg_type(m)),
//		m->header.ver,
//		m->header.messageLength,
//		m->header.domainNumber,
//		m->header.reserved1,
//		m->header.flagField[0],
//		m->header.flagField[1],
//		m->header.correction,
//		m->header.reserved2,
//		m->header.sourcePortIdentity,
		m->header.sequenceId
//		m->header.control,
//		m->header.logMessageInterval
		);
	fprintf(fp, "\n");
}

void msg_put(struct ptp_message *m)
{
	m->refcnt--;
	if (!m->refcnt) {
		pool_stats.count++;
		pool_debug("recycle", m);
		TAILQ_INSERT_HEAD(&msg_pool, m, list);
	}
}

int msg_sots_missing(struct ptp_message *m)
{
	int type = msg_type(m);
	switch (type) {
	case SYNC:
	case DELAY_REQ:
	case PDELAY_REQ:
	case PDELAY_RESP:
		break;
	case FOLLOW_UP:
	case DELAY_RESP:
	case PDELAY_RESP_FOLLOW_UP:
	case ANNOUNCE:
	case SIGNALING:
	case MANAGEMENT:
	default:
		return 0;
	}
	return msg_sots_valid(m) ? 0 : 1;
}
