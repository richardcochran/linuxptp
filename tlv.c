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
#include <string.h>

#include "port.h"
#include "tlv.h"

uint8_t ieee8021_id[3] = { IEEE_802_1_COMMITTEE };

static void scaled_ns_n2h(ScaledNs *sns)
{
	sns->nanoseconds_msb = ntohs(sns->nanoseconds_msb);
	sns->nanoseconds_lsb = net2host64(sns->nanoseconds_msb);
	sns->fractional_nanoseconds = ntohs(sns->fractional_nanoseconds);
}

static void scaled_ns_h2n(ScaledNs *sns)
{
	sns->nanoseconds_msb = htons(sns->nanoseconds_msb);
	sns->nanoseconds_lsb = host2net64(sns->nanoseconds_msb);
	sns->fractional_nanoseconds = htons(sns->fractional_nanoseconds);
}

static void mgt_post_recv(struct management_tlv *m)
{
	struct currentDS *cds;
	struct time_status_np *tsn;
	switch (m->id) {
	case CURRENT_DATA_SET:
		cds = (struct currentDS *) m->data;
		cds->stepsRemoved = ntohs(cds->stepsRemoved);
		cds->offsetFromMaster = net2host64(cds->offsetFromMaster);
		cds->meanPathDelay = net2host64(cds->meanPathDelay);
		break;
	case TIME_STATUS_NP:
		tsn = (struct time_status_np *) m->data;
		tsn->master_offset = net2host64(tsn->master_offset);
		tsn->ingress_time = net2host64(tsn->ingress_time);
		tsn->cumulativeScaledRateOffset = ntohl(tsn->cumulativeScaledRateOffset);
		tsn->scaledLastGmPhaseChange = ntohl(tsn->scaledLastGmPhaseChange);
		tsn->gmTimeBaseIndicator = ntohs(tsn->gmTimeBaseIndicator);
		scaled_ns_n2h(&tsn->lastGmPhaseChange);
		tsn->gmPresent = ntohl(tsn->gmPresent);
		break;
	}
}

static void mgt_pre_send(struct management_tlv *m)
{
	struct currentDS *cds;
	struct time_status_np *tsn;
	switch (m->id) {
	case CURRENT_DATA_SET:
		cds = (struct currentDS *) m->data;
		cds->stepsRemoved = htons(cds->stepsRemoved);
		cds->offsetFromMaster = host2net64(cds->offsetFromMaster);
		cds->meanPathDelay = host2net64(cds->meanPathDelay);
		break;
	case TIME_STATUS_NP:
		tsn = (struct time_status_np *) m->data;
		tsn->master_offset = host2net64(tsn->master_offset);
		tsn->ingress_time = host2net64(tsn->ingress_time);
		tsn->cumulativeScaledRateOffset = htonl(tsn->cumulativeScaledRateOffset);
		tsn->scaledLastGmPhaseChange = htonl(tsn->scaledLastGmPhaseChange);
		tsn->gmTimeBaseIndicator = htons(tsn->gmTimeBaseIndicator);
		scaled_ns_h2n(&tsn->lastGmPhaseChange);
		tsn->gmPresent = htonl(tsn->gmPresent);
		break;
	}
}

static void org_post_recv(struct organization_tlv *org)
{
	struct follow_up_info_tlv *f;

	if (0 == memcmp(org->id, ieee8021_id, sizeof(ieee8021_id))) {
		if (org->subtype[0] || org->subtype[1]) {
			return;
		}
		switch (org->subtype[2]) {
		case 1:
			f = (struct follow_up_info_tlv *) org;
			f->cumulativeScaledRateOffset = ntohl(f->cumulativeScaledRateOffset);
			f->gmTimeBaseIndicator = ntohs(f->gmTimeBaseIndicator);
			scaled_ns_n2h(&f->lastGmPhaseChange);
			f->scaledLastGmPhaseChange = ntohl(f->scaledLastGmPhaseChange);
			break;
		}
	}
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

void tlv_post_recv(struct TLV *tlv)
{
	struct management_tlv *mgt;
	struct management_error_status *mes;
	struct path_trace_tlv *ptt;

	switch (tlv->type) {
	case TLV_MANAGEMENT:
		mgt = (struct management_tlv *) tlv;
		mgt->id = ntohs(mgt->id);
		mgt_post_recv(mgt);
		break;
	case TLV_MANAGEMENT_ERROR_STATUS:
		mes = (struct management_error_status *) tlv;
		mes->error = ntohs(mes->error);
		mes->id = ntohs(mes->id);
		break;
	case TLV_ORGANIZATION_EXTENSION:
		org_post_recv((struct organization_tlv *) tlv);
		break;
	case TLV_REQUEST_UNICAST_TRANSMISSION:
	case TLV_GRANT_UNICAST_TRANSMISSION:
	case TLV_CANCEL_UNICAST_TRANSMISSION:
	case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
		break;
	case TLV_PATH_TRACE:
		ptt = (struct path_trace_tlv *) tlv;
		if (path_length(ptt) > PATH_TRACE_MAX) {
			ptt->length = PATH_TRACE_MAX * sizeof(struct ClockIdentity);
		}
		break;
	case TLV_ALTERNATE_TIME_OFFSET_INDICATOR:
	case TLV_AUTHENTICATION:
	case TLV_AUTHENTICATION_CHALLENGE:
	case TLV_SECURITY_ASSOCIATION_UPDATE:
	case TLV_CUM_FREQ_SCALE_FACTOR_OFFSET:
	default:
		break;
	}
}

void tlv_pre_send(struct TLV *tlv)
{
	struct management_tlv *mgt;
	struct management_error_status *mes;

	switch (tlv->type) {
	case TLV_MANAGEMENT:
		mgt = (struct management_tlv *) tlv;
		mgt_pre_send(mgt);
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
	case TLV_PATH_TRACE:
	case TLV_ALTERNATE_TIME_OFFSET_INDICATOR:
	case TLV_AUTHENTICATION:
	case TLV_AUTHENTICATION_CHALLENGE:
	case TLV_SECURITY_ASSOCIATION_UPDATE:
	case TLV_CUM_FREQ_SCALE_FACTOR_OFFSET:
	default:
		break;
	}
}
