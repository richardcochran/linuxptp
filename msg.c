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
#include <malloc.h>
#include <time.h>

#include <asm/byteorder.h>

#include "msg.h"

#define VERSION_MASK 0x0f
#define VERSION      0x02

static TAILQ_HEAD(msg_pool, ptp_message) msg_pool;

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

static int64_t host2net64(int64_t val)
{
	return __cpu_to_be64(val);
}

static int64_t net2host64(int64_t val)
{
	return __be64_to_cpu(val);
}

static int hdr_post_recv(struct ptp_header *m)
{
	if ((m->ver & VERSION_MASK) != VERSION)
		return -1;
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

static char *msg_type_string(int type)
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
	struct ptp_message *m = TAILQ_FIRST(&msg_pool);
	if (!m)
		m = malloc(sizeof(*m));
	if (m)
		m->refcnt = 1;
	return m;
}

void msg_get(struct ptp_message *m)
{
	m->refcnt++;
}

int msg_post_recv(struct ptp_message *m, int cnt)
{
	int type;

	if (cnt < sizeof(struct ptp_header))
		return -1;

	if (hdr_post_recv(&m->header))
		return -1;

	type = msg_type(m);

	switch (type) {
	case SYNC:
		if (cnt < sizeof(struct sync_msg))
			return -1;
		timestamp_post_recv(m, &m->sync.originTimestamp);
		break;
	case DELAY_REQ:
		if (cnt < sizeof(struct delay_req_msg))
			return -1;
		break;
	case PDELAY_REQ:
		if (cnt < sizeof(struct pdelay_req_msg))
			return -1;
		break;
	case PDELAY_RESP:
		if (cnt < sizeof(struct pdelay_resp_msg))
			return -1;
		break;
	case FOLLOW_UP:
		if (cnt < sizeof(struct follow_up_msg))
			return -1;
		timestamp_post_recv(m, &m->follow_up.preciseOriginTimestamp);
		break;
	case DELAY_RESP:
		if (cnt < sizeof(struct delay_resp_msg))
			return -1;
		timestamp_post_recv(m, &m->delay_resp.receiveTimestamp);
		break;
	case PDELAY_RESP_FOLLOW_UP:
		if (cnt < sizeof(struct pdelay_resp_fup_msg))
			return -1;
		break;
	case ANNOUNCE:
		if (cnt < sizeof(struct announce_msg))
			return -1;
		clock_gettime(CLOCK_MONOTONIC, &m->ts.host);
		timestamp_post_recv(m, &m->announce.originTimestamp);
		announce_post_recv(&m->announce);
		break;
	case SIGNALING:
	case MANAGEMENT:
	default:
		return -1;
	}
	return 0;
}

int msg_pre_send(struct ptp_message *m)
{
	int type;

	if (hdr_pre_send(&m->header))
		return -1;

	type = msg_type(m);

	switch (type) {
	case SYNC:
		break;
	case DELAY_REQ:
		break;
	case PDELAY_REQ:
	case PDELAY_RESP:
		return -1;
	case FOLLOW_UP:
		timestamp_pre_send(&m->follow_up.preciseOriginTimestamp);
		break;
	case DELAY_RESP:
		timestamp_pre_send(&m->delay_resp.receiveTimestamp);
		m->delay_resp.requestingPortIdentity.portNumber =
			htons(m->delay_resp.requestingPortIdentity.portNumber);
		break;
	case PDELAY_RESP_FOLLOW_UP:
		return -1;
	case ANNOUNCE:
		announce_pre_send(&m->announce);
		break;
	case SIGNALING:
	case MANAGEMENT:
	default:
		return -1;
	}
	return 0;
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
	if (!m)
		TAILQ_INSERT_HEAD(&msg_pool, m, list);
}
