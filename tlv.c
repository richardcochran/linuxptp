/**
 * @file tlv.c
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "port.h"
#include "tlv.h"
#include "msg.h"

#define HTONS(x) (x) = htons(x)
#define HTONL(x) (x) = htonl(x)
#define NTOHS(x) (x) = ntohs(x)
#define NTOHL(x) (x) = ntohl(x)

#define TLV_LENGTH_INVALID(tlv, type) \
	(tlv->length < sizeof(struct type) - sizeof(struct TLV))

uint8_t ieee8021_id[3] = { IEEE_802_1_COMMITTEE };

static TAILQ_HEAD(tlv_pool, tlv_extra) tlv_pool =
	TAILQ_HEAD_INITIALIZER(tlv_pool);

static void scaled_ns_n2h(ScaledNs *sns)
{
	sns->nanoseconds_msb = ntohs(sns->nanoseconds_msb);
	sns->nanoseconds_lsb = net2host64(sns->nanoseconds_lsb);
	sns->fractional_nanoseconds = ntohs(sns->fractional_nanoseconds);
}

static void scaled_ns_h2n(ScaledNs *sns)
{
	sns->nanoseconds_msb = htons(sns->nanoseconds_msb);
	sns->nanoseconds_lsb = host2net64(sns->nanoseconds_lsb);
	sns->fractional_nanoseconds = htons(sns->fractional_nanoseconds);
}

static void timestamp_host2net(struct Timestamp *t)
{
	HTONL(t->seconds_lsb);
	HTONS(t->seconds_msb);
	HTONL(t->nanoseconds);
}

static void timestamp_net2host(struct Timestamp *t)
{
	NTOHL(t->seconds_lsb);
	NTOHS(t->seconds_msb);
	NTOHL(t->nanoseconds);
}

static uint16_t flip16(void *p)
{
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	v = htons(v);
	memcpy(p, &v, sizeof(v));
	return v;
}

static int64_t host2net64_unaligned(void *p)
{
	int64_t v;
	memcpy(&v, p, sizeof(v));
	v = host2net64(v);
	memcpy(p, &v, sizeof(v));
	return v;
}

static int64_t net2host64_unaligned(void *p)
{
	int64_t v;
	memcpy(&v, p, sizeof(v));
	v = net2host64(v);
	memcpy(p, &v, sizeof(v));
	return v;
}

static size_t tlv_array_count(struct TLV *tlv, size_t base_size, size_t item_size)
{
	return (tlv->length - base_size) / item_size;
}

static bool tlv_array_invalid(struct TLV *tlv, size_t base_size, size_t item_size)
{
	size_t expected_length, n_items;

	n_items = tlv_array_count(tlv, base_size, item_size);

	expected_length = base_size + n_items * item_size;

	return (tlv->length == expected_length) ? false : true;
}

static int mgt_post_recv(struct management_tlv *m, uint16_t data_len,
			 struct tlv_extra *extra)
{
	struct grandmaster_settings_np *gsn;
	struct mgmt_clock_description *cd;
	struct subscribe_events_np *sen;
	struct port_properties_np *ppn;
	struct timePropertiesDS *tp;
	struct time_status_np *tsn;
	struct port_stats_np *psn;
	int extra_len = 0, i, len;
	struct port_ds_np *pdsnp;
	struct currentDS *cds;
	struct defaultDS *dds;
	struct parentDS *pds;
	struct portDS *p;
	uint8_t *buf;
	uint16_t u16;

	switch (m->id) {
	case MID_CLOCK_DESCRIPTION:
		cd = &extra->cd;
		buf = m->data;
		len = data_len;

		cd->clockType = (UInteger16 *) buf;
		buf += sizeof(*cd->clockType);
		len -= sizeof(*cd->clockType);
		if (len < 0)
			goto bad_length;
		flip16(cd->clockType);

		cd->physicalLayerProtocol = (struct PTPText *) buf;
		buf += sizeof(struct PTPText);
		len -= sizeof(struct PTPText);
		if (len < 0)
			goto bad_length;

		buf += cd->physicalLayerProtocol->length;
		len -= cd->physicalLayerProtocol->length;
		if (len < 0)
			goto bad_length;

		cd->physicalAddress = (struct PhysicalAddress *) buf;
		buf += sizeof(struct PhysicalAddress);
		len -= sizeof(struct PhysicalAddress);
		if (len < 0)
			goto bad_length;

		u16 = flip16(&cd->physicalAddress->length);
		if (u16 > TRANSPORT_ADDR_LEN)
			goto bad_length;
		buf += u16;
		len -= u16;
		if (len < 0)
			goto bad_length;

		cd->protocolAddress = (struct PortAddress *) buf;
		buf += sizeof(struct PortAddress);
		len -= sizeof(struct PortAddress);
		if (len < 0)
			goto bad_length;

		flip16(&cd->protocolAddress->networkProtocol);
		u16 = flip16(&cd->protocolAddress->addressLength);
		if (u16 > TRANSPORT_ADDR_LEN)
			goto bad_length;
		buf += u16;
		len -= u16;
		if (len < 0)
			goto bad_length;

		cd->manufacturerIdentity = buf;
		buf += OUI_LEN + 1;
		len -= OUI_LEN + 1;
		if (len < 0)
			goto bad_length;

		cd->productDescription = (struct PTPText *) buf;
		buf += sizeof(struct PTPText);
		len -= sizeof(struct PTPText);
		if (len < 0)
			goto bad_length;

		buf += cd->productDescription->length;
		len -= cd->productDescription->length;
		if (len < 0)
			goto bad_length;

		cd->revisionData = (struct PTPText *) buf;
		buf += sizeof(struct PTPText);
		len -= sizeof(struct PTPText);
		if (len < 0)
			goto bad_length;

		buf += cd->revisionData->length;
		len -= cd->revisionData->length;
		if (len < 0)
			goto bad_length;

		cd->userDescription = (struct PTPText *) buf;
		buf += sizeof(struct PTPText);
		len -= sizeof(struct PTPText);
		if (len < 0)
			goto bad_length;

		buf += cd->userDescription->length;
		len -= cd->userDescription->length;
		if (len < 0)
			goto bad_length;

		cd->profileIdentity = buf;
		buf += PROFILE_ID_LEN;
		len -= PROFILE_ID_LEN;
		if (len < 0)
			goto bad_length;

		extra_len = buf - m->data;
		break;
	case MID_USER_DESCRIPTION:
		if (data_len < sizeof(struct PTPText))
			goto bad_length;
		extra->cd.userDescription = (struct PTPText *) m->data;
		extra_len = sizeof(struct PTPText);
		extra_len += extra->cd.userDescription->length;
		break;
	case MID_DEFAULT_DATA_SET:
		if (data_len != sizeof(struct defaultDS))
			goto bad_length;
		dds = (struct defaultDS *) m->data;
		dds->numberPorts = ntohs(dds->numberPorts);
		dds->clockQuality.offsetScaledLogVariance =
			ntohs(dds->clockQuality.offsetScaledLogVariance);
		break;
	case MID_CURRENT_DATA_SET:
		if (data_len != sizeof(struct currentDS))
			goto bad_length;
		cds = (struct currentDS *) m->data;
		cds->stepsRemoved = ntohs(cds->stepsRemoved);
		cds->offsetFromMaster = net2host64(cds->offsetFromMaster);
		cds->meanPathDelay = net2host64(cds->meanPathDelay);
		break;
	case MID_PARENT_DATA_SET:
		if (data_len != sizeof(struct parentDS))
			goto bad_length;
		pds = (struct parentDS *) m->data;
		pds->parentPortIdentity.portNumber =
			ntohs(pds->parentPortIdentity.portNumber);
		pds->observedParentOffsetScaledLogVariance =
			ntohs(pds->observedParentOffsetScaledLogVariance);
		pds->observedParentClockPhaseChangeRate =
			ntohl(pds->observedParentClockPhaseChangeRate);
		pds->grandmasterClockQuality.offsetScaledLogVariance =
			ntohs(pds->grandmasterClockQuality.offsetScaledLogVariance);
		break;
	case MID_TIME_PROPERTIES_DATA_SET:
		if (data_len != sizeof(struct timePropertiesDS))
			goto bad_length;
		tp = (struct timePropertiesDS *) m->data;
		tp->currentUtcOffset = ntohs(tp->currentUtcOffset);
		break;
	case MID_PORT_DATA_SET:
		if (data_len != sizeof(struct portDS))
			goto bad_length;
		p = (struct portDS *) m->data;
		p->portIdentity.portNumber = ntohs(p->portIdentity.portNumber);
		p->peerMeanPathDelay = net2host64(p->peerMeanPathDelay);
		break;
	case MID_TIME_STATUS_NP:
		if (data_len != sizeof(struct time_status_np))
			goto bad_length;
		tsn = (struct time_status_np *) m->data;
		tsn->master_offset = net2host64(tsn->master_offset);
		tsn->ingress_time = net2host64(tsn->ingress_time);
		tsn->cumulativeScaledRateOffset = ntohl(tsn->cumulativeScaledRateOffset);
		tsn->scaledLastGmPhaseChange = ntohl(tsn->scaledLastGmPhaseChange);
		tsn->gmTimeBaseIndicator = ntohs(tsn->gmTimeBaseIndicator);
		scaled_ns_n2h(&tsn->lastGmPhaseChange);
		tsn->gmPresent = ntohl(tsn->gmPresent);
		break;
	case MID_GRANDMASTER_SETTINGS_NP:
		if (data_len != sizeof(struct grandmaster_settings_np))
			goto bad_length;
		gsn = (struct grandmaster_settings_np *) m->data;
		gsn->clockQuality.offsetScaledLogVariance =
			ntohs(gsn->clockQuality.offsetScaledLogVariance);
		gsn->utc_offset = ntohs(gsn->utc_offset);
		break;
	case MID_PORT_DATA_SET_NP:
		if (data_len != sizeof(struct port_ds_np))
			goto bad_length;
		pdsnp = (struct port_ds_np *) m->data;
		pdsnp->neighborPropDelayThresh = ntohl(pdsnp->neighborPropDelayThresh);
		pdsnp->asCapable = ntohl(pdsnp->asCapable);
		break;
	case MID_SUBSCRIBE_EVENTS_NP:
		if (data_len != sizeof(struct subscribe_events_np))
			goto bad_length;
		sen = (struct subscribe_events_np *)m->data;
		sen->duration = ntohs(sen->duration);
		break;
	case MID_PORT_PROPERTIES_NP:
		if (data_len < sizeof(struct port_properties_np))
			goto bad_length;
		ppn = (struct port_properties_np *)m->data;
		ppn->portIdentity.portNumber = ntohs(ppn->portIdentity.portNumber);
		extra_len = sizeof(struct port_properties_np);
		extra_len += ppn->interface.length;
		break;
	case MID_PORT_STATS_NP:
		if (data_len < sizeof(struct port_stats_np))
			goto bad_length;
		psn = (struct port_stats_np *)m->data;
		psn->portIdentity.portNumber =
			ntohs(psn->portIdentity.portNumber);
		for (i = 0 ; i < MAX_MESSAGE_TYPES; i++) {
			psn->stats.rxMsgType[i] = __le64_to_cpu(psn->stats.rxMsgType[i]);
			psn->stats.txMsgType[i] = __le64_to_cpu(psn->stats.txMsgType[i]);
		}
		extra_len = sizeof(struct port_stats_np);
		break;
	case MID_SAVE_IN_NON_VOLATILE_STORAGE:
	case MID_RESET_NON_VOLATILE_STORAGE:
	case MID_INITIALIZE:
	case MID_FAULT_LOG_RESET:
	case MID_ENABLE_PORT:
	case MID_DISABLE_PORT:
		if (data_len != 0)
			goto bad_length;
		break;
	}
	if (extra_len) {
		if (extra_len % 2)
			extra_len++;
		if (extra_len + sizeof(m->id) != m->length)
			goto bad_length;
	}
	return 0;
bad_length:
	return -EBADMSG;
}

static void mgt_pre_send(struct management_tlv *m, struct tlv_extra *extra)
{
	struct grandmaster_settings_np *gsn;
	struct mgmt_clock_description *cd;
	struct subscribe_events_np *sen;
	struct port_properties_np *ppn;
	struct timePropertiesDS *tp;
	struct time_status_np *tsn;
	struct port_stats_np *psn;
	struct port_ds_np *pdsnp;
	struct defaultDS *dds;
	struct currentDS *cds;
	struct parentDS *pds;
	struct portDS *p;
	int i;

	switch (m->id) {
	case MID_CLOCK_DESCRIPTION:
		if (extra) {
			cd = &extra->cd;
			flip16(cd->clockType);
			flip16(&cd->physicalAddress->length);
			flip16(&cd->protocolAddress->networkProtocol);
			flip16(&cd->protocolAddress->addressLength);
		}
		break;
	case MID_DEFAULT_DATA_SET:
		dds = (struct defaultDS *) m->data;
		dds->numberPorts = htons(dds->numberPorts);
		dds->clockQuality.offsetScaledLogVariance =
			htons(dds->clockQuality.offsetScaledLogVariance);
		break;
	case MID_CURRENT_DATA_SET:
		cds = (struct currentDS *) m->data;
		cds->stepsRemoved = htons(cds->stepsRemoved);
		cds->offsetFromMaster = host2net64(cds->offsetFromMaster);
		cds->meanPathDelay = host2net64(cds->meanPathDelay);
		break;
	case MID_PARENT_DATA_SET:
		pds = (struct parentDS *) m->data;
		pds->parentPortIdentity.portNumber =
			htons(pds->parentPortIdentity.portNumber);
		pds->observedParentOffsetScaledLogVariance =
			htons(pds->observedParentOffsetScaledLogVariance);
		pds->observedParentClockPhaseChangeRate =
			htonl(pds->observedParentClockPhaseChangeRate);
		pds->grandmasterClockQuality.offsetScaledLogVariance =
			htons(pds->grandmasterClockQuality.offsetScaledLogVariance);
		break;
	case MID_TIME_PROPERTIES_DATA_SET:
		tp = (struct timePropertiesDS *) m->data;
		tp->currentUtcOffset = htons(tp->currentUtcOffset);
		break;
	case MID_PORT_DATA_SET:
		p = (struct portDS *) m->data;
		p->portIdentity.portNumber = htons(p->portIdentity.portNumber);
		p->peerMeanPathDelay = host2net64(p->peerMeanPathDelay);
		break;
	case MID_TIME_STATUS_NP:
		tsn = (struct time_status_np *) m->data;
		tsn->master_offset = host2net64(tsn->master_offset);
		tsn->ingress_time = host2net64(tsn->ingress_time);
		tsn->cumulativeScaledRateOffset = htonl(tsn->cumulativeScaledRateOffset);
		tsn->scaledLastGmPhaseChange = htonl(tsn->scaledLastGmPhaseChange);
		tsn->gmTimeBaseIndicator = htons(tsn->gmTimeBaseIndicator);
		scaled_ns_h2n(&tsn->lastGmPhaseChange);
		tsn->gmPresent = htonl(tsn->gmPresent);
		break;
	case MID_GRANDMASTER_SETTINGS_NP:
		gsn = (struct grandmaster_settings_np *) m->data;
		gsn->clockQuality.offsetScaledLogVariance =
			htons(gsn->clockQuality.offsetScaledLogVariance);
		gsn->utc_offset = htons(gsn->utc_offset);
		break;
	case MID_PORT_DATA_SET_NP:
		pdsnp = (struct port_ds_np *) m->data;
		pdsnp->neighborPropDelayThresh = htonl(pdsnp->neighborPropDelayThresh);
		pdsnp->asCapable = htonl(pdsnp->asCapable);
		break;
	case MID_SUBSCRIBE_EVENTS_NP:
		sen = (struct subscribe_events_np *)m->data;
		sen->duration = htons(sen->duration);
		break;
	case MID_PORT_PROPERTIES_NP:
		ppn = (struct port_properties_np *)m->data;
		ppn->portIdentity.portNumber = htons(ppn->portIdentity.portNumber);
		break;
	case MID_PORT_STATS_NP:
		psn = (struct port_stats_np *)m->data;
		psn->portIdentity.portNumber =
			htons(psn->portIdentity.portNumber);
		for (i = 0 ; i < MAX_MESSAGE_TYPES; i++) {
			psn->stats.rxMsgType[i] = __cpu_to_le64(psn->stats.rxMsgType[i]);
			psn->stats.txMsgType[i] = __cpu_to_le64(psn->stats.txMsgType[i]);
		}
		break;
	}
}

static int nsm_resp_post_recv(struct tlv_extra *extra)
{
	struct nsm_resp_tlv_head *head;
	struct TLV *tlv = extra->tlv;
	struct timePropertiesDS *tp;
	struct PortAddress *paddr;
	struct currentDS *cds;
	struct parentDS *pds;
	unsigned char *ptr;
	uint16_t expected;

	if (tlv->length < sizeof(*head) + sizeof(*extra->foot)
	    - sizeof(head->type) - sizeof(head->length)) {
		return -EBADMSG;
	}
	head = (struct nsm_resp_tlv_head *) tlv;
	paddr = &head->parent_addr;
	NTOHS(paddr->networkProtocol);
	NTOHS(paddr->addressLength);

	switch (paddr->networkProtocol) {
	case TRANS_UDP_IPV4:
		expected = 4;
		break;
	case TRANS_UDP_IPV6:
		expected = 16;
		break;
	case TRANS_IEEE_802_3:
		expected = 6;
		break;
	default:
		return -EBADMSG;
	}
	if (paddr->addressLength != expected) {
		return -EBADMSG;
	}
	if (tlv->length != sizeof(*head) + sizeof(*extra->foot) +
	    paddr->addressLength - sizeof(head->type) - sizeof(head->length)) {
		return -EBADMSG;
	}

	ptr = (unsigned char *) tlv;
	ptr += sizeof(*head) + paddr->addressLength;
	extra->foot = (struct nsm_resp_tlv_foot *) ptr;

	pds = &extra->foot->parent;
	cds = &extra->foot->current;
	tp = &extra->foot->timeprop;

	/*
	 * At this point the alignment only 2 bytes worst case.
	 * So we need to be careful with the 64 bit words.
	 */
	NTOHS(pds->parentPortIdentity.portNumber);
	NTOHS(pds->observedParentOffsetScaledLogVariance);
	NTOHL(pds->observedParentClockPhaseChangeRate);
	NTOHS(pds->grandmasterClockQuality.offsetScaledLogVariance);

	NTOHS(cds->stepsRemoved);
	net2host64_unaligned(&cds->offsetFromMaster);
	net2host64_unaligned(&cds->meanPathDelay);

	NTOHS(tp->currentUtcOffset);

	NTOHL(extra->foot->lastsync.seconds_lsb);
	NTOHS(extra->foot->lastsync.seconds_msb);
	NTOHL(extra->foot->lastsync.nanoseconds);

	return 0;
}

static void nsm_resp_pre_send(struct tlv_extra *extra)
{
	struct nsm_resp_tlv_head *head;
	struct timePropertiesDS *tp;
	struct PortAddress *paddr;
	struct currentDS *cds;
	struct parentDS *pds;

	head = (struct nsm_resp_tlv_head *) extra->tlv;
	paddr = &head->parent_addr;

	pds = &extra->foot->parent;
	cds = &extra->foot->current;
	tp = &extra->foot->timeprop;

	NTOHS(paddr->networkProtocol);
	NTOHS(paddr->addressLength);

	HTONS(pds->parentPortIdentity.portNumber);
	HTONS(pds->observedParentOffsetScaledLogVariance);
	HTONL(pds->observedParentClockPhaseChangeRate);
	HTONS(pds->grandmasterClockQuality.offsetScaledLogVariance);

	HTONS(cds->stepsRemoved);
	host2net64_unaligned(&cds->offsetFromMaster);
	host2net64_unaligned(&cds->meanPathDelay);

	HTONS(tp->currentUtcOffset);

	HTONL(extra->foot->lastsync.seconds_lsb);
	HTONS(extra->foot->lastsync.seconds_msb);
	HTONL(extra->foot->lastsync.nanoseconds);
}

static int org_post_recv(struct organization_tlv *org)
{
	struct follow_up_info_tlv *f;

	if (0 == memcmp(org->id, ieee8021_id, sizeof(ieee8021_id))) {
		if (org->subtype[0] || org->subtype[1]) {
			return 0;
		}
		switch (org->subtype[2]) {
		case 1:
			if (org->length + sizeof(struct TLV) != sizeof(struct follow_up_info_tlv))
				goto bad_length;
			f = (struct follow_up_info_tlv *) org;
			f->cumulativeScaledRateOffset = ntohl(f->cumulativeScaledRateOffset);
			f->gmTimeBaseIndicator = ntohs(f->gmTimeBaseIndicator);
			scaled_ns_n2h(&f->lastGmPhaseChange);
			f->scaledLastGmPhaseChange = ntohl(f->scaledLastGmPhaseChange);
			break;

		case 2:
			if (org->length + sizeof(struct TLV) != sizeof(struct msg_interval_req_tlv))
				goto bad_length;
		}
	}
	return 0;
bad_length:
	return -EBADMSG;
}

static void org_pre_send(struct organization_tlv *org)
{
	struct follow_up_info_tlv *f;

	if (0 == memcmp(org->id, ieee8021_id, sizeof(ieee8021_id))) {
		if (org->subtype[0] || org->subtype[1]) {
			return;
		}
		switch (org->subtype[2]) {
		case 1:
			f = (struct follow_up_info_tlv *) org;
			f->cumulativeScaledRateOffset = htonl(f->cumulativeScaledRateOffset);
			f->gmTimeBaseIndicator = htons(f->gmTimeBaseIndicator);
			scaled_ns_h2n(&f->lastGmPhaseChange);
			f->scaledLastGmPhaseChange = htonl(f->scaledLastGmPhaseChange);
			break;
		}
	}
}

static int slave_delay_timing_data_post_revc(struct tlv_extra *extra)
{
	struct slave_delay_timing_data_tlv *slave_delay =
		(struct slave_delay_timing_data_tlv *) extra->tlv;
	size_t base_size = sizeof(slave_delay->sourcePortIdentity), n_items;
	struct slave_delay_timing_record *record;

	if (tlv_array_invalid(extra->tlv, base_size, sizeof(*record))) {
		return -EBADMSG;
	}
	n_items = tlv_array_count(extra->tlv, base_size, sizeof(*record));
	record = slave_delay->record;

	NTOHS(slave_delay->sourcePortIdentity.portNumber);

	while (n_items) {
		NTOHS(record->sequenceId);
		timestamp_net2host(&record->delayOriginTimestamp);
		net2host64_unaligned(&record->totalCorrectionField);
		timestamp_net2host(&record->delayResponseTimestamp);
		n_items--;
		record++;
	}

	return 0;
}

static void slave_delay_timing_data_pre_send(struct tlv_extra *extra)
{
	struct slave_delay_timing_data_tlv *slave_delay =
		(struct slave_delay_timing_data_tlv *) extra->tlv;
	size_t base_size = sizeof(slave_delay->sourcePortIdentity), n_items;
	struct slave_delay_timing_record *record;

	n_items = tlv_array_count(extra->tlv, base_size, sizeof(*record));
	record = slave_delay->record;

	HTONS(slave_delay->sourcePortIdentity.portNumber);

	while (n_items) {
		HTONS(record->sequenceId);
		timestamp_host2net(&record->delayOriginTimestamp);
		host2net64_unaligned(&record->totalCorrectionField);
		timestamp_host2net(&record->delayResponseTimestamp);
		n_items--;
		record++;
	}
}

static int slave_rx_sync_timing_data_post_revc(struct tlv_extra *extra)
{
	struct slave_rx_sync_timing_data_tlv *slave_data =
		(struct slave_rx_sync_timing_data_tlv *) extra->tlv;
	size_t base_size = sizeof(slave_data->sourcePortIdentity), n_items;
	struct slave_rx_sync_timing_record *record;

	if (tlv_array_invalid(extra->tlv, base_size, sizeof(*record))) {
		return -EBADMSG;
	}
	n_items = tlv_array_count(extra->tlv, base_size, sizeof(*record));
	record = slave_data->record;

	NTOHS(slave_data->sourcePortIdentity.portNumber);

	while (n_items) {
		NTOHS(record->sequenceId);
		timestamp_net2host(&record->syncOriginTimestamp);
		net2host64_unaligned(&record->totalCorrectionField);
		NTOHL(record->scaledCumulativeRateOffset);
		timestamp_net2host(&record->syncEventIngressTimestamp);
		n_items--;
		record++;
	}

	return 0;
}

static void slave_rx_sync_timing_data_pre_send(struct tlv_extra *extra)
{
	struct slave_rx_sync_timing_data_tlv *slave_data =
		(struct slave_rx_sync_timing_data_tlv *) extra->tlv;
	size_t base_size = sizeof(slave_data->sourcePortIdentity), n_items;
	struct slave_rx_sync_timing_record *record;

	n_items = tlv_array_count(extra->tlv, base_size, sizeof(*record));
	record = slave_data->record;

	HTONS(slave_data->sourcePortIdentity.portNumber);

	while (n_items) {
		HTONS(record->sequenceId);
		timestamp_host2net(&record->syncOriginTimestamp);
		host2net64_unaligned(&record->totalCorrectionField);
		HTONL(record->scaledCumulativeRateOffset);
		timestamp_host2net(&record->syncEventIngressTimestamp);
		n_items--;
		record++;
	}
}

static int unicast_message_type_valid(uint8_t message_type)
{
	message_type >>= 4;
	switch (message_type) {
	case ANNOUNCE:
	case SYNC:
	case DELAY_RESP:
	case PDELAY_RESP:
		return 1;
	default:
		return 0;
	}
}

static int unicast_negotiation_post_recv(struct tlv_extra *extra)
{
	struct request_unicast_xmit_tlv *request;
	struct ack_cancel_unicast_xmit_tlv *ack;
	struct cancel_unicast_xmit_tlv *cancel;
	struct grant_unicast_xmit_tlv *grant;
	struct TLV *tlv = extra->tlv;

	switch (tlv->type) {
	case TLV_REQUEST_UNICAST_TRANSMISSION:
		if (TLV_LENGTH_INVALID(tlv, request_unicast_xmit_tlv)) {
			return -EBADMSG;
		}
		request = (struct request_unicast_xmit_tlv *) tlv;
		if (!unicast_message_type_valid(request->message_type)) {
			return -EBADMSG;
		}
		NTOHL(request->durationField);
		break;
	case TLV_GRANT_UNICAST_TRANSMISSION:
		if (TLV_LENGTH_INVALID(tlv, grant_unicast_xmit_tlv)) {
			return -EBADMSG;
		}
		grant = (struct grant_unicast_xmit_tlv *) tlv;
		if (!unicast_message_type_valid(grant->message_type)) {
			return -EBADMSG;
		}
		NTOHL(grant->durationField);
		break;
	case TLV_CANCEL_UNICAST_TRANSMISSION:
		if (TLV_LENGTH_INVALID(tlv, cancel_unicast_xmit_tlv)) {
			return -EBADMSG;
		}
		cancel = (struct cancel_unicast_xmit_tlv *) tlv;
		if (!unicast_message_type_valid(cancel->message_type_flags)) {
			return -EBADMSG;
		}
		break;
	case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
		if (TLV_LENGTH_INVALID(tlv, ack_cancel_unicast_xmit_tlv)) {
			return -EBADMSG;
		}
		ack = (struct ack_cancel_unicast_xmit_tlv *) tlv;
		if (!unicast_message_type_valid(ack->message_type_flags)) {
			return -EBADMSG;
		}
		break;
	}
	return 0;
}

static void unicast_negotiation_pre_send(struct TLV *tlv)
{
	struct request_unicast_xmit_tlv *request;
	struct grant_unicast_xmit_tlv *grant;

	switch (tlv->type) {
	case TLV_REQUEST_UNICAST_TRANSMISSION:
		request = (struct request_unicast_xmit_tlv *) tlv;
		HTONL(request->durationField);
		break;
	case TLV_GRANT_UNICAST_TRANSMISSION:
		grant = (struct grant_unicast_xmit_tlv *) tlv;
		HTONL(grant->durationField);
		break;
	case TLV_CANCEL_UNICAST_TRANSMISSION:
	case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
		break;
	}
}

struct tlv_extra *tlv_extra_alloc(void)
{
	struct tlv_extra *extra = TAILQ_FIRST(&tlv_pool);

	if (extra) {
		TAILQ_REMOVE(&tlv_pool, extra, list);
	} else {
		extra = calloc(1, sizeof(*extra));
	}
	return extra;
}

void tlv_extra_cleanup(void)
{
	struct tlv_extra *extra;

	while ((extra = TAILQ_FIRST(&tlv_pool)) != NULL) {
		TAILQ_REMOVE(&tlv_pool, extra, list);
		free(extra);
	}
}

void tlv_extra_recycle(struct tlv_extra *extra)
{
	memset(extra, 0, sizeof(*extra));
	TAILQ_INSERT_HEAD(&tlv_pool, extra, list);
}

int tlv_post_recv(struct tlv_extra *extra)
{
	struct management_error_status *mes;
	struct TLV *tlv = extra->tlv;
	struct management_tlv *mgt;
	int result = 0;

	switch (tlv->type) {
	case TLV_MANAGEMENT:
		if (TLV_LENGTH_INVALID(tlv, management_tlv))
			goto bad_length;
		mgt = (struct management_tlv *) tlv;
		mgt->id = ntohs(mgt->id);
		if (tlv->length > sizeof(mgt->id))
			result = mgt_post_recv(mgt, tlv->length - sizeof(mgt->id), extra);
		break;
	case TLV_MANAGEMENT_ERROR_STATUS:
		if (TLV_LENGTH_INVALID(tlv, management_error_status))
			goto bad_length;
		mes = (struct management_error_status *) tlv;
		mes->error = ntohs(mes->error);
		mes->id = ntohs(mes->id);
		break;
	case TLV_ORGANIZATION_EXTENSION:
		if (TLV_LENGTH_INVALID(tlv, organization_tlv))
			goto bad_length;
		result = org_post_recv((struct organization_tlv *) tlv);
		break;
	case TLV_REQUEST_UNICAST_TRANSMISSION:
	case TLV_GRANT_UNICAST_TRANSMISSION:
	case TLV_CANCEL_UNICAST_TRANSMISSION:
	case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
		result = unicast_negotiation_post_recv(extra);
		break;
	case TLV_PATH_TRACE:
		if (tlv_array_invalid(tlv, 0, sizeof(struct ClockIdentity))) {
			goto bad_length;
		}
		break;
	case TLV_ALTERNATE_TIME_OFFSET_INDICATOR:
	case TLV_AUTHENTICATION_2008:
	case TLV_AUTHENTICATION_CHALLENGE:
	case TLV_SECURITY_ASSOCIATION_UPDATE:
	case TLV_CUM_FREQ_SCALE_FACTOR_OFFSET:
	case TLV_PTPMON_REQ:
		break;
	case TLV_PTPMON_RESP:
		result = nsm_resp_post_recv(extra);
		break;
	case TLV_ORGANIZATION_EXTENSION_PROPAGATE:
	case TLV_ENHANCED_ACCURACY_METRICS:
	case TLV_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE:
	case TLV_L1_SYNC:
	case TLV_PORT_COMMUNICATION_AVAILABILITY:
	case TLV_PROTOCOL_ADDRESS:
		break;
	case TLV_SLAVE_RX_SYNC_TIMING_DATA:
		result = slave_rx_sync_timing_data_post_revc(extra);
		break;
	case TLV_SLAVE_RX_SYNC_COMPUTED_DATA:
	case TLV_SLAVE_TX_EVENT_TIMESTAMPS:
		break;
	case TLV_SLAVE_DELAY_TIMING_DATA_NP:
		result = slave_delay_timing_data_post_revc(extra);
		break;
	case TLV_CUMULATIVE_RATE_RATIO:
	case TLV_PAD:
	case TLV_AUTHENTICATION:
	default:
		break;
	}
	return result;
bad_length:
	return -EBADMSG;
}

void tlv_pre_send(struct TLV *tlv, struct tlv_extra *extra)
{
	struct management_tlv *mgt;
	struct management_error_status *mes;

	switch (tlv->type) {
	case TLV_MANAGEMENT:
		mgt = (struct management_tlv *) tlv;
		if (tlv->length > sizeof(mgt->id))
			mgt_pre_send(mgt, extra);
		mgt->id = htons(mgt->id);
		break;
	case TLV_MANAGEMENT_ERROR_STATUS:
		mes = (struct management_error_status *) tlv;
		mes->error = htons(mes->error);
		mes->id = htons(mes->id);
		break;
	case TLV_ORGANIZATION_EXTENSION:
		org_pre_send((struct organization_tlv *) tlv);
		break;
	case TLV_REQUEST_UNICAST_TRANSMISSION:
	case TLV_GRANT_UNICAST_TRANSMISSION:
	case TLV_CANCEL_UNICAST_TRANSMISSION:
	case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
		unicast_negotiation_pre_send(tlv);
		break;
	case TLV_PATH_TRACE:
	case TLV_ALTERNATE_TIME_OFFSET_INDICATOR:
	case TLV_AUTHENTICATION_2008:
	case TLV_AUTHENTICATION_CHALLENGE:
	case TLV_SECURITY_ASSOCIATION_UPDATE:
	case TLV_CUM_FREQ_SCALE_FACTOR_OFFSET:
	case TLV_PTPMON_REQ:
		break;
	case TLV_PTPMON_RESP:
		nsm_resp_pre_send(extra);
		break;
	case TLV_ORGANIZATION_EXTENSION_PROPAGATE:
	case TLV_ENHANCED_ACCURACY_METRICS:
	case TLV_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE:
	case TLV_L1_SYNC:
	case TLV_PORT_COMMUNICATION_AVAILABILITY:
	case TLV_PROTOCOL_ADDRESS:
		break;
	case TLV_SLAVE_RX_SYNC_TIMING_DATA:
		slave_rx_sync_timing_data_pre_send(extra);
		break;
	case TLV_SLAVE_RX_SYNC_COMPUTED_DATA:
	case TLV_SLAVE_TX_EVENT_TIMESTAMPS:
		break;
	case TLV_SLAVE_DELAY_TIMING_DATA_NP:
		slave_delay_timing_data_pre_send(extra);
		break;
	case TLV_CUMULATIVE_RATE_RATIO:
	case TLV_PAD:
	case TLV_AUTHENTICATION:
	default:
		break;
	}
}
