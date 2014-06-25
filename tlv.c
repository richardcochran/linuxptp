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
#include <string.h>

#include "port.h"
#include "tlv.h"
#include "msg.h"

#define TLV_LENGTH_INVALID(tlv, type) \
	(tlv->length < sizeof(struct type) - sizeof(struct TLV))

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

static uint16_t flip16(uint16_t *p) {
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	v = htons(v);
	memcpy(p, &v, sizeof(v));
	return v;
}

static int mgt_post_recv(struct management_tlv *m, uint16_t data_len,
			 struct tlv_extra *extra)
{
	struct defaultDS *dds;
	struct currentDS *cds;
	struct parentDS *pds;
	struct timePropertiesDS *tp;
	struct portDS *p;
	struct port_ds_np *pdsnp;
	struct time_status_np *tsn;
	struct grandmaster_settings_np *gsn;
	struct subscribe_events_np *sen;
	struct port_properties_np *ppn;
	struct mgmt_clock_description *cd;
	int extra_len = 0, len;
	uint8_t *buf;
	uint16_t u16;
	switch (m->id) {
	case TLV_CLOCK_DESCRIPTION:
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
	case TLV_USER_DESCRIPTION:
		if (data_len < sizeof(struct PTPText))
			goto bad_length;
		extra->cd.userDescription = (struct PTPText *) m->data;
		extra_len = sizeof(struct PTPText);
		extra_len += extra->cd.userDescription->length;
		break;
	case TLV_DEFAULT_DATA_SET:
		if (data_len != sizeof(struct defaultDS))
			goto bad_length;
		dds = (struct defaultDS *) m->data;
		dds->numberPorts = ntohs(dds->numberPorts);
		dds->clockQuality.offsetScaledLogVariance =
			ntohs(dds->clockQuality.offsetScaledLogVariance);
		break;
	case TLV_CURRENT_DATA_SET:
		if (data_len != sizeof(struct currentDS))
			goto bad_length;
		cds = (struct currentDS *) m->data;
		cds->stepsRemoved = ntohs(cds->stepsRemoved);
		cds->offsetFromMaster = net2host64(cds->offsetFromMaster);
		cds->meanPathDelay = net2host64(cds->meanPathDelay);
		break;
	case TLV_PARENT_DATA_SET:
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
	case TLV_TIME_PROPERTIES_DATA_SET:
		if (data_len != sizeof(struct timePropertiesDS))
			goto bad_length;
		tp = (struct timePropertiesDS *) m->data;
		tp->currentUtcOffset = ntohs(tp->currentUtcOffset);
		break;
	case TLV_PORT_DATA_SET:
		if (data_len != sizeof(struct portDS))
			goto bad_length;
		p = (struct portDS *) m->data;
		p->portIdentity.portNumber = ntohs(p->portIdentity.portNumber);
		p->peerMeanPathDelay = net2host64(p->peerMeanPathDelay);
		break;
	case TLV_TIME_STATUS_NP:
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
	case TLV_GRANDMASTER_SETTINGS_NP:
		if (data_len != sizeof(struct grandmaster_settings_np))
			goto bad_length;
		gsn = (struct grandmaster_settings_np *) m->data;
		gsn->clockQuality.offsetScaledLogVariance =
			ntohs(gsn->clockQuality.offsetScaledLogVariance);
		gsn->utc_offset = ntohs(gsn->utc_offset);
		break;
	case TLV_PORT_DATA_SET_NP:
		if (data_len != sizeof(struct port_ds_np))
			goto bad_length;
		pdsnp = (struct port_ds_np *) m->data;
		pdsnp->neighborPropDelayThresh = ntohl(pdsnp->neighborPropDelayThresh);
		pdsnp->asCapable = ntohl(pdsnp->asCapable);
		break;
	case TLV_SUBSCRIBE_EVENTS_NP:
		if (data_len != sizeof(struct subscribe_events_np))
			goto bad_length;
		sen = (struct subscribe_events_np *)m->data;
		sen->duration = ntohs(sen->duration);
		break;
	case TLV_PORT_PROPERTIES_NP:
		if (data_len < sizeof(struct port_properties_np))
			goto bad_length;
		ppn = (struct port_properties_np *)m->data;
		ppn->portIdentity.portNumber = ntohs(ppn->portIdentity.portNumber);
		extra_len = sizeof(struct port_properties_np);
		extra_len += ppn->interface.length;
		break;
	case TLV_SAVE_IN_NON_VOLATILE_STORAGE:
	case TLV_RESET_NON_VOLATILE_STORAGE:
	case TLV_INITIALIZE:
	case TLV_FAULT_LOG_RESET:
	case TLV_ENABLE_PORT:
	case TLV_DISABLE_PORT:
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
	struct defaultDS *dds;
	struct currentDS *cds;
	struct parentDS *pds;
	struct timePropertiesDS *tp;
	struct portDS *p;
	struct port_ds_np *pdsnp;
	struct time_status_np *tsn;
	struct grandmaster_settings_np *gsn;
	struct subscribe_events_np *sen;
	struct port_properties_np *ppn;
	struct mgmt_clock_description *cd;
	switch (m->id) {
	case TLV_CLOCK_DESCRIPTION:
		if (extra) {
			cd = &extra->cd;
			flip16(cd->clockType);
			flip16(&cd->physicalAddress->length);
			flip16(&cd->protocolAddress->networkProtocol);
			flip16(&cd->protocolAddress->addressLength);
		}
		break;
	case TLV_DEFAULT_DATA_SET:
		dds = (struct defaultDS *) m->data;
		dds->numberPorts = htons(dds->numberPorts);
		dds->clockQuality.offsetScaledLogVariance =
			htons(dds->clockQuality.offsetScaledLogVariance);
		break;
	case TLV_CURRENT_DATA_SET:
		cds = (struct currentDS *) m->data;
		cds->stepsRemoved = htons(cds->stepsRemoved);
		cds->offsetFromMaster = host2net64(cds->offsetFromMaster);
		cds->meanPathDelay = host2net64(cds->meanPathDelay);
		break;
	case TLV_PARENT_DATA_SET:
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
	case TLV_TIME_PROPERTIES_DATA_SET:
		tp = (struct timePropertiesDS *) m->data;
		tp->currentUtcOffset = htons(tp->currentUtcOffset);
		break;
	case TLV_PORT_DATA_SET:
		p = (struct portDS *) m->data;
		p->portIdentity.portNumber = htons(p->portIdentity.portNumber);
		p->peerMeanPathDelay = host2net64(p->peerMeanPathDelay);
		break;
	case TLV_TIME_STATUS_NP:
		tsn = (struct time_status_np *) m->data;
		tsn->master_offset = host2net64(tsn->master_offset);
		tsn->ingress_time = host2net64(tsn->ingress_time);
		tsn->cumulativeScaledRateOffset = htonl(tsn->cumulativeScaledRateOffset);
		tsn->scaledLastGmPhaseChange = htonl(tsn->scaledLastGmPhaseChange);
		tsn->gmTimeBaseIndicator = htons(tsn->gmTimeBaseIndicator);
		scaled_ns_h2n(&tsn->lastGmPhaseChange);
		tsn->gmPresent = htonl(tsn->gmPresent);
		break;
	case TLV_GRANDMASTER_SETTINGS_NP:
		gsn = (struct grandmaster_settings_np *) m->data;
		gsn->clockQuality.offsetScaledLogVariance =
			htons(gsn->clockQuality.offsetScaledLogVariance);
		gsn->utc_offset = htons(gsn->utc_offset);
		break;
	case TLV_PORT_DATA_SET_NP:
		pdsnp = (struct port_ds_np *) m->data;
		pdsnp->neighborPropDelayThresh = htonl(pdsnp->neighborPropDelayThresh);
		pdsnp->asCapable = htonl(pdsnp->asCapable);
		break;
	case TLV_SUBSCRIBE_EVENTS_NP:
		sen = (struct subscribe_events_np *)m->data;
		sen->duration = htons(sen->duration);
		break;
	case TLV_PORT_PROPERTIES_NP:
		ppn = (struct port_properties_np *)m->data;
		ppn->portIdentity.portNumber = htons(ppn->portIdentity.portNumber);
		break;
	}
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

int tlv_post_recv(struct TLV *tlv, struct tlv_extra *extra)
{
	int result = 0;
	struct management_tlv *mgt;
	struct management_error_status *mes;
	struct path_trace_tlv *ptt;
	struct tlv_extra dummy_extra;
	if (!extra)
		extra = &dummy_extra;

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
