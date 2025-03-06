/**
 * @file pmc.c
 * @brief PTP management client program
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
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "ds.h"
#include "fsm.h"
#include "notification.h"
#include "pmc_common.h"
#include "print.h"
#include "sad.h"
#include "tlv.h"
#include "uds.h"
#include "util.h"
#include "version.h"

static struct pmc *pmc;

#define IFMT "\n\t\t"
#define P41 ((double)(1ULL << 41))

static char *text2str(struct PTPText *text)
{
	static struct static_ptp_text s;
	s.max_symbols = -1;
	static_ptp_text_copy(&s, text);
	return (char*)(s.text);
}

static char *bin2str(Octet *data, int len)
{
	static char buf[BIN_BUF_SIZE];
	return bin2str_impl(data, len, buf, sizeof(buf));
}

#define SHOW_TIMESTAMP(ts) \
	((uint64_t)ts.seconds_lsb) | (((uint64_t)ts.seconds_msb) << 32), ts.nanoseconds

static void pmc_show_delay_timing(struct slave_delay_timing_record *record,
				  int fd)
{
	dprintf(fd,
		IFMT "sequenceId                 %hu"
		IFMT "delayOriginTimestamp       %" PRId64 ".%09u"
		IFMT "totalCorrectionField       %" PRId64
		IFMT "delayResponseTimestamp     %" PRId64 ".%09u",
		record->sequenceId,
		SHOW_TIMESTAMP(record->delayOriginTimestamp),
		record->totalCorrectionField >> 16,
		SHOW_TIMESTAMP(record->delayResponseTimestamp));
}

static void pmc_show_rx_sync_timing(struct slave_rx_sync_timing_record *record,
				    int fd)
{
	dprintf(fd,
		IFMT "sequenceId                 %hu"
		IFMT "syncOriginTimestamp        %" PRId64 ".%09u"
		IFMT "totalCorrectionField       %" PRId64
		IFMT "scaledCumulativeRateOffset %u"
		IFMT "syncEventIngressTimestamp  %" PRId64 ".%09u",
		record->sequenceId,
		SHOW_TIMESTAMP(record->syncOriginTimestamp),
		record->totalCorrectionField >> 16,
		record->scaledCumulativeRateOffset,
		SHOW_TIMESTAMP(record->syncEventIngressTimestamp));
}


static void pmc_show_unicast_master_entry(struct unicast_master_entry *entry,
				    int fd)
{
	dprintf(fd,
		IFMT "%s %-24s %-34s %-9s %-10hhu 0x%02hhx         0x%04hx                  %-3hhu %-3hhu",
		entry->selected ? "yes" : "no ",
		pid2str(&entry->port_identity),
		portaddr2str(&entry->address),
		ustate2str(entry->port_state),
		entry->clock_quality.clockClass,
		entry->clock_quality.clockAccuracy,
		entry->clock_quality.offsetScaledLogVariance,
		entry->priority1,
		entry->priority2
	);
}

static void pmc_show_signaling(struct ptp_message *msg, int fd)
{
	struct slave_rx_sync_timing_record *sync_record;
	struct slave_delay_timing_record *delay_record;
	struct slave_rx_sync_timing_data_tlv *srstd;
	struct slave_delay_timing_data_tlv *sdtdt;
	struct tlv_extra *extra;
	int i, cnt;

	dprintf(fd, "\t%s seq %hu %s ",
		pid2str(&msg->header.sourcePortIdentity),
		msg->header.sequenceId, "SIGNALING");

	TAILQ_FOREACH(extra, &msg->tlv_list, list) {
		switch (extra->tlv->type) {
		case TLV_SLAVE_RX_SYNC_TIMING_DATA:
			srstd = (struct slave_rx_sync_timing_data_tlv *) extra->tlv;
			cnt = (srstd->length - sizeof(srstd->sourcePortIdentity)) /
				sizeof(*sync_record);
				dprintf(fd, "SLAVE_RX_SYNC_TIMING_DATA N %d "
				IFMT "sourcePortIdentity         %s",
				cnt, pid2str(&srstd->sourcePortIdentity));
			sync_record = srstd->record;
			for (i = 0; i < cnt; i++) {
				pmc_show_rx_sync_timing(sync_record, fd);
				sync_record++;
			}
			break;
		case TLV_SLAVE_DELAY_TIMING_DATA_NP:
			sdtdt = (struct slave_delay_timing_data_tlv *) extra->tlv;
			cnt = (sdtdt->length - sizeof(sdtdt->sourcePortIdentity)) /
				sizeof(*delay_record);
				dprintf(fd, "SLAVE_DELAY_TIMING_DATA_NP N %d "
				IFMT "sourcePortIdentity         %s",
				cnt, pid2str(&sdtdt->sourcePortIdentity));
			delay_record = sdtdt->record;
			for (i = 0; i < cnt; i++) {
				pmc_show_delay_timing(delay_record, fd);
				delay_record++;
			}
			break;
		default:
			break;
		}
	}
	dprintf(fd, "\n");
	// fflush(fp);
}

static void pmc_show(struct ptp_message *msg, int fd)
{
	struct external_grandmaster_properties_np *egpn;
	struct alternate_time_offset_properties *atop;
	struct alternate_time_offset_name *aton;
	struct ieee_c37_238_settings_np *pwr;
	struct unicast_master_table_np *umtn;
	struct grandmaster_settings_np *gsn;
	struct port_service_stats_np *pssp;
	struct mgmt_clock_description *cd;
	struct management_tlv_datum *mtd;
	struct unicast_master_entry *ume;
	struct subscribe_events_np *sen;
	struct port_corrections_np *pcn;
	struct port_properties_np *ppn;
	struct port_hwclock_np *phn;
	struct cmlds_info_np *cmlds;
	struct timePropertiesDS *tp;
	struct management_tlv *mgt;
	struct time_status_np *tsn;
	struct port_stats_np *pcp;
	struct tlv_extra *extra;
	struct port_ds_np *pnp;
	struct defaultDS *dds;
	struct currentDS *cds;
	struct parentDS *pds;
	uint64_t next_jump;
	struct portDS *p;
	struct TLV *tlv;
	int action, i;
	uint8_t *buf;

	if (msg_type(msg) == SIGNALING) {
		pmc_show_signaling(msg, fd);
		return;
	}
	if (msg_type(msg) != MANAGEMENT) {
		return;
	}
	action = management_action(msg);
	if (action < GET || action > ACKNOWLEDGE) {
		return;
	}
	dprintf(fd, "\t%s seq %hu %s ",
		pid2str(&msg->header.sourcePortIdentity),
		msg->header.sequenceId, pmc_action_string(action));
	switch (msg_tlv_count(msg)) {
	case 1:
		break;
	case 2:
		extra = TAILQ_LAST(&msg->tlv_list, tlv_list);
		if (extra->tlv->type == TLV_AUTHENTICATION) {
			break;
		}
	default:
		goto out;
	}
	extra = TAILQ_FIRST(&msg->tlv_list);
	tlv = (struct TLV *) msg->management.suffix;
	if (tlv->type == TLV_MANAGEMENT) {
		dprintf(fd, "MANAGEMENT ");
	} else if (tlv->type == TLV_MANAGEMENT_ERROR_STATUS) {
		dprintf(fd, "MANAGEMENT_ERROR_STATUS ");
		goto out;
	} else {
		dprintf(fd, "unknown-tlv ");
		goto out;
	}
	mgt = (struct management_tlv *) msg->management.suffix;
	if (mgt->length == 2 && mgt->id != MID_NULL_MANAGEMENT) {
		dprintf(fd, "empty-tlv ");
		goto out;
	}
	switch (mgt->id) {
	case MID_CLOCK_DESCRIPTION:
		cd = &extra->cd;
		dprintf(fd, "CLOCK_DESCRIPTION "
			IFMT "clockType             0x%hx"
			IFMT "physicalLayerProtocol %s"
			IFMT "physicalAddress       %s"
			IFMT "protocolAddress       %hu %s",
			align16(cd->clockType),
			text2str(cd->physicalLayerProtocol),
			bin2str(cd->physicalAddress->address,
				align16(&cd->physicalAddress->length)),
			align16(&cd->protocolAddress->networkProtocol),
			portaddr2str(cd->protocolAddress));
		dprintf(fd, IFMT "manufacturerId        %s"
			IFMT "productDescription    %s",
			bin2str(cd->manufacturerIdentity, OUI_LEN),
			text2str(cd->productDescription));
		dprintf(fd, IFMT "revisionData          %s",
			text2str(cd->revisionData));
		dprintf(fd, IFMT "userDescription       %s"
			IFMT "profileId             %s",
			text2str(cd->userDescription),
			bin2str(cd->profileIdentity, PROFILE_ID_LEN));
		break;
	case MID_USER_DESCRIPTION:
		dprintf(fd, "USER_DESCRIPTION "
			IFMT "userDescription  %s",
			text2str(extra->cd.userDescription));
		break;
	case MID_DEFAULT_DATA_SET:
		dds = (struct defaultDS *) mgt->data;
		dprintf(fd, "DEFAULT_DATA_SET "
			IFMT "twoStepFlag             %d"
			IFMT "slaveOnly               %d"
			IFMT "numberPorts             %hu"
			IFMT "priority1               %hhu"
			IFMT "clockClass              %hhu"
			IFMT "clockAccuracy           0x%02hhx"
			IFMT "offsetScaledLogVariance 0x%04hx"
			IFMT "priority2               %hhu"
			IFMT "clockIdentity           %s"
			IFMT "domainNumber            %hhu",
			dds->flags & DDS_TWO_STEP_FLAG ? 1 : 0,
			dds->flags & DDS_SLAVE_ONLY ? 1 : 0,
			dds->numberPorts,
			dds->priority1,
			dds->clockQuality.clockClass,
			dds->clockQuality.clockAccuracy,
			dds->clockQuality.offsetScaledLogVariance,
			dds->priority2,
			cid2str(&dds->clockIdentity),
			dds->domainNumber);
		break;
	case MID_CURRENT_DATA_SET:
		cds = (struct currentDS *) mgt->data;
		dprintf(fd, "CURRENT_DATA_SET "
			IFMT "stepsRemoved     %hd"
			IFMT "offsetFromMaster %.1f"
			IFMT "meanPathDelay    %.1f",
			cds->stepsRemoved, cds->offsetFromMaster / 65536.0,
			cds->meanPathDelay / 65536.0);
		break;
	case MID_PARENT_DATA_SET:
		pds = (struct parentDS *) mgt->data;
		dprintf(fd, "PARENT_DATA_SET "
			IFMT "parentPortIdentity                    %s"
			IFMT "parentStats                           %hhu"
			IFMT "observedParentOffsetScaledLogVariance 0x%04hx"
			IFMT "observedParentClockPhaseChangeRate    0x%08x"
			IFMT "grandmasterPriority1                  %hhu"
			IFMT "gm.ClockClass                         %hhu"
			IFMT "gm.ClockAccuracy                      0x%02hhx"
			IFMT "gm.OffsetScaledLogVariance            0x%04hx"
			IFMT "grandmasterPriority2                  %hhu"
			IFMT "grandmasterIdentity                   %s",
			pid2str(&pds->parentPortIdentity),
			pds->parentStats,
			pds->observedParentOffsetScaledLogVariance,
			pds->observedParentClockPhaseChangeRate,
			pds->grandmasterPriority1,
			pds->grandmasterClockQuality.clockClass,
			pds->grandmasterClockQuality.clockAccuracy,
			pds->grandmasterClockQuality.offsetScaledLogVariance,
			pds->grandmasterPriority2,
			cid2str(&pds->grandmasterIdentity));
		break;
	case MID_TIME_PROPERTIES_DATA_SET:
		tp = (struct timePropertiesDS *) mgt->data;
		dprintf(fd, "TIME_PROPERTIES_DATA_SET "
			IFMT "currentUtcOffset      %hd"
			IFMT "leap61                %d"
			IFMT "leap59                %d"
			IFMT "currentUtcOffsetValid %d"
			IFMT "ptpTimescale          %d"
			IFMT "timeTraceable         %d"
			IFMT "frequencyTraceable    %d"
			IFMT "timeSource            0x%02hhx",
			tp->currentUtcOffset,
			tp->flags & LEAP_61 ? 1 : 0,
			tp->flags & LEAP_59 ? 1 : 0,
			tp->flags & UTC_OFF_VALID ? 1 : 0,
			tp->flags & PTP_TIMESCALE ? 1 : 0,
			tp->flags & TIME_TRACEABLE ? 1 : 0,
			tp->flags & FREQ_TRACEABLE ? 1 : 0,
			tp->timeSource);
		break;
	case MID_PRIORITY1:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "PRIORITY1 "
			IFMT "priority1 %hhu", mtd->val);
		break;
	case MID_PRIORITY2:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "PRIORITY2 "
			IFMT "priority2 %hhu", mtd->val);
		break;
	case MID_DOMAIN:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "DOMAIN "
			IFMT "domainNumber %hhu", mtd->val);
		break;
	case MID_SLAVE_ONLY:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "SLAVE_ONLY "
			IFMT "slaveOnly %d", mtd->val);
		break;
	case MID_CLOCK_ACCURACY:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "CLOCK_ACCURACY "
			IFMT "clockAccuracy 0x%02hhx", mtd->val);
		break;
	case MID_TRACEABILITY_PROPERTIES:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "TRACEABILITY_PROPERTIES "
			IFMT "timeTraceable      %d"
			IFMT "frequencyTraceable %d",
			mtd->val & TIME_TRACEABLE ? 1 : 0,
			mtd->val & FREQ_TRACEABLE ? 1 : 0);
		break;
	case MID_TIMESCALE_PROPERTIES:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "TIMESCALE_PROPERTIES "
			IFMT "ptpTimescale %d", mtd->val & PTP_TIMESCALE ? 1 : 0);
		break;
	case MID_ALTERNATE_TIME_OFFSET_ENABLE:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "ALTERNATE_TIME_OFFSET_ENABLE "
			IFMT "keyField       %hhu"
			IFMT "enable         %d",
			mtd->val,
			mtd->reserved & 1 ? 1 : 0);
		break;
	case MID_ALTERNATE_TIME_OFFSET_NAME:
		aton = (struct alternate_time_offset_name *) mgt->data;
		dprintf(fd, "ALTERNATE_TIME_OFFSET_NAME "
			IFMT "keyField       %hhu"
			IFMT "displayName    %s",
			aton->keyField,
			text2str(&aton->displayName));
		break;
	case MID_ALTERNATE_TIME_OFFSET_PROPERTIES:
		atop = (struct alternate_time_offset_properties *) mgt->data;
		next_jump = atop->timeOfNextJump.seconds_msb;
		next_jump <<= 32;
		next_jump |= atop->timeOfNextJump.seconds_lsb;
		dprintf(fd, "ALTERNATE_TIME_OFFSET_PROPERTIES "
			IFMT "keyField       %hhu"
			IFMT "currentOffset  %d"
			IFMT "jumpSeconds    %d"
			IFMT "timeOfNextJump %" PRIu64,
			atop->keyField,
			align32(&atop->currentOffset),
			align32(&atop->jumpSeconds),
			next_jump);
		break;
	case MID_MASTER_ONLY:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "MASTER_ONLY "
			IFMT "masterOnly %d", mtd->val);
		break;
	case MID_TIME_STATUS_NP:
		tsn = (struct time_status_np *) mgt->data;
		dprintf(fd, "TIME_STATUS_NP "
			IFMT "master_offset              %" PRId64
			IFMT "ingress_time               %" PRId64
			IFMT "cumulativeScaledRateOffset %+.9f"
			IFMT "scaledLastGmPhaseChange    %d"
			IFMT "gmTimeBaseIndicator        %hu"
			IFMT "lastGmPhaseChange          0x%04hx'%016" PRIx64 ".%04hx"
			IFMT "gmPresent                  %s"
			IFMT "gmIdentity                 %s",
			tsn->master_offset,
			tsn->ingress_time,
			(tsn->cumulativeScaledRateOffset + 0.0) / P41,
			tsn->scaledLastGmPhaseChange,
			tsn->gmTimeBaseIndicator,
			tsn->lastGmPhaseChange.nanoseconds_msb,
			tsn->lastGmPhaseChange.nanoseconds_lsb,
			tsn->lastGmPhaseChange.fractional_nanoseconds,
			tsn->gmPresent ? "true" : "false",
			cid2str(&tsn->gmIdentity));
		break;
	case MID_GRANDMASTER_SETTINGS_NP:
		gsn = (struct grandmaster_settings_np *) mgt->data;
		dprintf(fd, "GRANDMASTER_SETTINGS_NP "
			IFMT "clockClass              %hhu"
			IFMT "clockAccuracy           0x%02hhx"
			IFMT "offsetScaledLogVariance 0x%04hx"
			IFMT "currentUtcOffset        %hd"
			IFMT "leap61                  %d"
			IFMT "leap59                  %d"
			IFMT "currentUtcOffsetValid   %d"
			IFMT "ptpTimescale            %d"
			IFMT "timeTraceable           %d"
			IFMT "frequencyTraceable      %d"
			IFMT "timeSource              0x%02hhx",
			gsn->clockQuality.clockClass,
			gsn->clockQuality.clockAccuracy,
			gsn->clockQuality.offsetScaledLogVariance,
			gsn->utc_offset,
			gsn->time_flags & LEAP_61 ? 1 : 0,
			gsn->time_flags & LEAP_59 ? 1 : 0,
			gsn->time_flags & UTC_OFF_VALID ? 1 : 0,
			gsn->time_flags & PTP_TIMESCALE ? 1 : 0,
			gsn->time_flags & TIME_TRACEABLE ? 1 : 0,
			gsn->time_flags & FREQ_TRACEABLE ? 1 : 0,
			gsn->time_source);
		break;
	case MID_SUBSCRIBE_EVENTS_NP:
		sen = (struct subscribe_events_np *) mgt->data;
		dprintf(fd, "SUBSCRIBE_EVENTS_NP "
			IFMT "duration               %hu"
			IFMT "NOTIFY_PORT_STATE      %s"
			IFMT "NOTIFY_TIME_SYNC       %s"
			IFMT "NOTIFY_PARENT_DATA_SET %s"
			IFMT "NOTIFY_CMLDS           %s",
			sen->duration,
			event_bitmask_get(sen->bitmask, NOTIFY_PORT_STATE) ? "on" : "off",
			event_bitmask_get(sen->bitmask, NOTIFY_TIME_SYNC) ? "on" : "off",
			event_bitmask_get(sen->bitmask, NOTIFY_PARENT_DATA_SET) ? "on" : "off",
			event_bitmask_get(sen->bitmask, NOTIFY_CMLDS) ? "on" : "off");
		break;
	case MID_SYNCHRONIZATION_UNCERTAIN_NP:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "SYNCHRONIZATION_UNCERTAIN_NP "
			IFMT "uncertain %hhu", mtd->val);
		break;
		case MID_EXTERNAL_GRANDMASTER_PROPERTIES_NP:
		egpn = (struct external_grandmaster_properties_np *) mgt->data;
		dprintf(fd, "EXTERNAL_GRANDMASTER_PROPERTIES_NP "
			IFMT "gmIdentity   %s"
			IFMT "stepsRemoved %hu",
			cid2str(&egpn->gmIdentity),
			egpn->stepsRemoved);
		break;
	case MID_PORT_DATA_SET:
		p = (struct portDS *) mgt->data;
		if (p->portState > PS_SLAVE) {
			p->portState = 0;
		}
		dprintf(fd, "PORT_DATA_SET "
			IFMT "portIdentity            %s"
			IFMT "portState               %s"
			IFMT "logMinDelayReqInterval  %hhd"
			IFMT "peerMeanPathDelay       %" PRId64
			IFMT "logAnnounceInterval     %hhd"
			IFMT "announceReceiptTimeout  %hhu"
			IFMT "logSyncInterval         %hhd"
			IFMT "delayMechanism          %hhu"
			IFMT "logMinPdelayReqInterval %hhd"
			IFMT "versionNumber           %u",
			pid2str(&p->portIdentity), ps_str[p->portState],
			p->logMinDelayReqInterval, p->peerMeanPathDelay >> 16,
			p->logAnnounceInterval, p->announceReceiptTimeout,
			p->logSyncInterval, p->delayMechanism,
			p->logMinPdelayReqInterval,
			p->versionNumber & MAJOR_VERSION_MASK);
		break;
	case MID_PORT_DATA_SET_NP:
		pnp = (struct port_ds_np *) mgt->data;
		dprintf(fd, "PORT_DATA_SET_NP "
			IFMT "neighborPropDelayThresh %u"
			IFMT "asCapable               %d",
			pnp->neighborPropDelayThresh,
			pnp->asCapable ? 1 : 0);
		break;
	case MID_PORT_PROPERTIES_NP:
		ppn = (struct port_properties_np *) mgt->data;
		if (ppn->port_state > PS_SLAVE) {
			ppn->port_state = 0;
		}
		dprintf(fd, "PORT_PROPERTIES_NP "
			IFMT "portIdentity            %s"
			IFMT "portState               %s"
			IFMT "timestamping            %s"
			IFMT "interface               %s",
			pid2str(&ppn->portIdentity),
			ps_str[ppn->port_state],
			ts_str(ppn->timestamping),
			text2str(&ppn->interface));
		break;
	case MID_PORT_STATS_NP:
		pcp = (struct port_stats_np *) mgt->data;
		dprintf(fd, "PORT_STATS_NP "
			IFMT "portIdentity              %s"
			IFMT "rx_Sync                   %" PRIu64
			IFMT "rx_Delay_Req              %" PRIu64
			IFMT "rx_Pdelay_Req             %" PRIu64
			IFMT "rx_Pdelay_Resp            %" PRIu64
			IFMT "rx_Follow_Up              %" PRIu64
			IFMT "rx_Delay_Resp             %" PRIu64
			IFMT "rx_Pdelay_Resp_Follow_Up  %" PRIu64
			IFMT "rx_Announce               %" PRIu64
			IFMT "rx_Signaling              %" PRIu64
			IFMT "rx_Management             %" PRIu64
			IFMT "tx_Sync                   %" PRIu64
			IFMT "tx_Delay_Req              %" PRIu64
			IFMT "tx_Pdelay_Req             %" PRIu64
			IFMT "tx_Pdelay_Resp            %" PRIu64
			IFMT "tx_Follow_Up              %" PRIu64
			IFMT "tx_Delay_Resp             %" PRIu64
			IFMT "tx_Pdelay_Resp_Follow_Up  %" PRIu64
			IFMT "tx_Announce               %" PRIu64
			IFMT "tx_Signaling              %" PRIu64
			IFMT "tx_Management             %" PRIu64,
			pid2str(&pcp->portIdentity),
			pcp->stats.rxMsgType[SYNC],
			pcp->stats.rxMsgType[DELAY_REQ],
			pcp->stats.rxMsgType[PDELAY_REQ],
			pcp->stats.rxMsgType[PDELAY_RESP],
			pcp->stats.rxMsgType[FOLLOW_UP],
			pcp->stats.rxMsgType[DELAY_RESP],
			pcp->stats.rxMsgType[PDELAY_RESP_FOLLOW_UP],
			pcp->stats.rxMsgType[ANNOUNCE],
			pcp->stats.rxMsgType[SIGNALING],
			pcp->stats.rxMsgType[MANAGEMENT],
			pcp->stats.txMsgType[SYNC],
			pcp->stats.txMsgType[DELAY_REQ],
			pcp->stats.txMsgType[PDELAY_REQ],
			pcp->stats.txMsgType[PDELAY_RESP],
			pcp->stats.txMsgType[FOLLOW_UP],
			pcp->stats.txMsgType[DELAY_RESP],
			pcp->stats.txMsgType[PDELAY_RESP_FOLLOW_UP],
			pcp->stats.txMsgType[ANNOUNCE],
			pcp->stats.txMsgType[SIGNALING],
			pcp->stats.txMsgType[MANAGEMENT]);
		break;
	case MID_PORT_SERVICE_STATS_NP:
		pssp = (struct port_service_stats_np *) mgt->data;
		dprintf(fd, "PORT_SERVICE_STATS_NP "
		IFMT "portIdentity              %s"
		IFMT "announce_timeout          %" PRIu64
		IFMT "sync_timeout              %" PRIu64
		IFMT "delay_timeout             %" PRIu64
		IFMT "unicast_service_timeout   %" PRIu64
		IFMT "unicast_request_timeout   %" PRIu64
		IFMT "master_announce_timeout   %" PRIu64
		IFMT "master_sync_timeout       %" PRIu64
		IFMT "qualification_timeout     %" PRIu64
		IFMT "sync_mismatch             %" PRIu64
		IFMT "followup_mismatch         %" PRIu64,
		pid2str(&pssp->portIdentity),
		pssp->stats.announce_timeout,
		pssp->stats.sync_timeout,
		pssp->stats.delay_timeout,
		pssp->stats.unicast_service_timeout,
		pssp->stats.unicast_request_timeout,
		pssp->stats.master_announce_timeout,
		pssp->stats.master_sync_timeout,
		pssp->stats.qualification_timeout,
		pssp->stats.sync_mismatch,
		pssp->stats.followup_mismatch);
		break;
	case MID_UNICAST_MASTER_TABLE_NP:
		umtn = (struct unicast_master_table_np *) mgt->data;
		dprintf(fd, "UNICAST_MASTER_TABLE_NP "
			IFMT "actual_table_size %hu",
			umtn->actual_table_size);
		buf = (uint8_t *) umtn->unicast_masters;
		// table header
		dprintf(fd,
			IFMT "%s  %-24s %-34s %-9s %s %s %s %s  %s",
			"BM", "identity", "address", "state",
			"clockClass", "clockQuality", "offsetScaledLogVariance",
			"p1", "p2");
		for (i = 0; i < umtn->actual_table_size; i++) {
			ume = (struct unicast_master_entry *) buf;
			pmc_show_unicast_master_entry(ume, fd);
			buf += sizeof(*ume) + ume->address.addressLength;
		}
		break;
	case MID_PORT_HWCLOCK_NP:
		phn = (struct port_hwclock_np *) mgt->data;
		dprintf(fd, "PORT_HWCLOCK_NP "
			IFMT "portIdentity            %s"
			IFMT "phcIndex                %d"
			IFMT "flags                   %hhu",
			pid2str(&phn->portIdentity),
			phn->phc_index,
			phn->flags);
		break;
	case MID_POWER_PROFILE_SETTINGS_NP:
		pwr = (struct ieee_c37_238_settings_np *) mgt->data;
		dprintf(fd, "POWER_PROFILE_SETTINGS_NP "
			IFMT "version                   %hu"
			IFMT "grandmasterID             0x%04hx"
			IFMT "grandmasterTimeInaccuracy %u"
			IFMT "networkTimeInaccuracy     %u"
			IFMT "totalTimeInaccuracy       %u",
			pwr->version,
			pwr->grandmasterID,
			pwr->grandmasterTimeInaccuracy,
			pwr->networkTimeInaccuracy,
			pwr->totalTimeInaccuracy);
		break;
	case MID_CMLDS_INFO_NP:
		cmlds = (struct cmlds_info_np *) mgt->data;
		dprintf(fd, "CMLDS_INFO_NP "
			IFMT "meanLinkDelay           %" PRId64
			IFMT "scaledNeighborRateRatio %" PRId32
			IFMT "as_capable              %" PRIu32,
			cmlds->meanLinkDelay >> 16,
			cmlds->scaledNeighborRateRatio,
			cmlds->as_capable);
		break;
	case MID_PORT_CORRECTIONS_NP:
		pcn = (struct port_corrections_np *) mgt->data;
		dprintf(fd, "PORT_CORRECTIONS_NP "
			IFMT "egressLatency  %"PRId64" "
			IFMT "ingressLatency %"PRId64" "
			IFMT "delayAsymmetry %"PRId64" ",
			pcn->egressLatency >> 16,
			pcn->ingressLatency >> 16,
			pcn->delayAsymmetry >> 16);
		break;
	case MID_LOG_ANNOUNCE_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "LOG_ANNOUNCE_INTERVAL "
			IFMT "logAnnounceInterval %hhd", mtd->val);
		break;
	case MID_ANNOUNCE_RECEIPT_TIMEOUT:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "ANNOUNCE_RECEIPT_TIMEOUT "
			IFMT "announceReceiptTimeout %hhu", mtd->val);
		break;
	case MID_LOG_SYNC_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "LOG_SYNC_INTERVAL "
			IFMT "logSyncInterval %hhd", mtd->val);
		break;
	case MID_VERSION_NUMBER:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "VERSION_NUMBER "
			IFMT "versionNumber %hhu", mtd->val & MAJOR_VERSION_MASK);
		break;
	case MID_DELAY_MECHANISM:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "DELAY_MECHANISM "
			IFMT "delayMechanism %hhu", mtd->val);
		break;
	case MID_LOG_MIN_PDELAY_REQ_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		dprintf(fd, "LOG_MIN_PDELAY_REQ_INTERVAL "
			IFMT "logMinPdelayReqInterval %hhd", mtd->val);
		break;
	}
out:
	dprintf(fd, "\n");
	// fflush(fp);
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options] [commands]\n\n"
		" Network Transport\n\n"
		" -2        IEEE 802.3\n"
		" -4        UDP IPV4 (default)\n"
		" -6        UDP IPV6\n"
		" -u        UDS local\n\n"
		" Other Options\n\n"
		" -b [num]  boundary hops, default 1\n"
		" -c [path] listen to commands on this socket\n"
		" -d [num]  domain number, default 0\n"
		" -f [file] read configuration from 'file'\n"
		" -h        prints this message and exits\n"
		" -i [dev]  interface device to use, default 'eth0'\n"
		"           for network and '/var/run/pmc.$pid' for UDS.\n"
		" -s [path] server address for UDS, default '/var/run/ptp4l'.\n"
		" -t [hex]  transport specific field, default 0x0\n"
		" -v        prints the software version and exits\n"
		" -z        send zero length TLV values with the GET actions\n"
		"\n",
		progname);
}

// handle_nonblock and xread come from git source, gplv2
int handle_nonblock(int fd, short poll_events, int err)
{
    struct pollfd pfd;

    if (err != EAGAIN && err != EWOULDBLOCK) {
        return 0;
    }

    pfd.fd = fd;
    pfd.events = poll_events;

    /*
     * no need to check for errors, here;
     * a subsequent read/write will detect unrecoverable errors
     */
    poll(&pfd, 1, -1);
    return 1;
}

/*
 * xread() is the same a read(), but it automatically restarts read()
 * operations with a recoverable error (EAGAIN and EINTR). xread()
 * DOES NOT GUARANTEE that "len" bytes is read even if the data is available.
 */
ssize_t xread(int fd, void* buf, size_t len)
{
    ssize_t nr;
    if (len > 8096) {
        len = 8096;
    }
    while (1) {
        nr = read(fd, buf, len);
        if (nr < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (handle_nonblock(fd, POLLIN, errno)) {
                continue;
            }
        }
        return nr;
    }
}

int main(int argc, char *argv[])
{
	const char *iface_name = NULL;
	char *config = NULL, *progname;
	int c, cnt, index, length, tmo = -1, batch_mode = 0, zero_datalen = 0;
	int ret = 0;
	char line[1024], *command = NULL, uds_local[MAX_IFNAME_SIZE + 1];
	enum transport_type transport_type = TRANS_UDP_IPV4;
	UInteger8 boundary_hops = 1, domain_number = 0, transport_specific = 0, allow_unauth = 0;
	struct ptp_message *msg;
	struct option *opts;
	struct config *cfg;
	char const *command_socket_path = NULL;
	int command_socket_fd = -1;
	bool use_command_socket = false;
	int remote_fd = -1;

#define N_FD 3
	struct pollfd pollfd[N_FD];

	handle_term_signals();

	cfg = config_create();
	if (!cfg) {
		return -1;
	}

	opts = config_long_options(cfg);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv, "246u""b:c:d:f:hi:s:t:vz",
				       opts, &index))) {
		switch (c) {
		case 0:
			if (config_parse_option(cfg, opts[index].name, optarg)) {
				ret = -1;
				goto out;
			}
			break;
		case '2':
			if (config_set_int(cfg, "network_transport", TRANS_IEEE_802_3)) {
				ret = -1;
				goto out;
			}
			break;
		case '4':
			if (config_set_int(cfg, "network_transport", TRANS_UDP_IPV4)) {
				ret = -1;
				goto out;
			}
			break;
		case '6':
			if (config_set_int(cfg, "network_transport", TRANS_UDP_IPV6)) {
				ret = -1;
				goto out;
			}
			break;
		case 'u':
			if (config_set_int(cfg, "network_transport", TRANS_UDS)) {
				ret = -1;
				goto out;
			}
			break;
		case 'b':
			boundary_hops = atoi(optarg);
			break;
		case 'c':
			command_socket_path=optarg;
			use_command_socket = true;
			break;
		case 'd':
			if (config_set_int(cfg, "domainNumber", atoi(optarg))) {
				ret = -1;
				goto out;
			}
			break;
		case 'f':
			config = optarg;
			break;
		case 'i':
			iface_name = optarg;
			break;
		case 's':
			if (strlen(optarg) > MAX_IFNAME_SIZE) {
				fprintf(stderr, "path %s too long, max is %d\n",
					optarg, MAX_IFNAME_SIZE);
				config_destroy(cfg);
				return -1;
			}
			if (config_set_string(cfg, "uds_address", optarg)) {
				config_destroy(cfg);
				return -1;
			}
			break;
		case 't':
			if (1 == sscanf(optarg, "%x", &c)) {
				if (config_set_int(cfg, "transportSpecific", c)) {
					ret = -1;
					goto out;
				}
			}
			break;
		case 'v':
			version_show(stdout);
			config_destroy(cfg);
			return 0;
		case 'z':
			zero_datalen = 1;
			break;
		case 'h':
			usage(progname);
			config_destroy(cfg);
			return 0;
		case '?':
		default:
			usage(progname);
			config_destroy(cfg);
			return -1;
		}
	}

	if (config && (c = config_read(config, cfg))) {
		config_destroy(cfg);
		return -1;
	}

	transport_type = config_get_int(cfg, NULL, "network_transport");
	transport_specific = config_get_int(cfg, NULL, "transportSpecific") << 4;
	domain_number = config_get_int(cfg, NULL, "domainNumber");
	allow_unauth = config_get_int(cfg, NULL, "allow_unauth");

	if (sad_create(cfg)) {
		goto out;
	}

	if (!iface_name) {
		if (transport_type == TRANS_UDS) {
			snprintf(uds_local, sizeof(uds_local),
				 "/var/run/pmc.%d", getpid());
			iface_name = uds_local;
		} else {
			iface_name = "eth0";
		}
	}
	if (optind < argc) {
		batch_mode = 1;
	}

	print_set_progname(progname);
	print_set_syslog(1);
	print_set_verbose(1);

	if (use_command_socket) {
		if (batch_mode) {
			pr_emerg("Command socket doesn't make sense in batch mode.\n");
			return -1;
		}

		// will communicate with uds at command_socket_path instead of stdin/out

		// remove old socket
		unlink(command_socket_path);

		// create socket and bind it to provided path
		command_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		struct sockaddr_un sockaddr;
		memset(&sockaddr, 0, sizeof(struct sockaddr_un));
		sockaddr.sun_family = AF_UNIX;
		strncpy(sockaddr.sun_path, command_socket_path, sizeof(sockaddr.sun_path) - 1);
		int rc = bind(command_socket_fd, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_un));
		if (rc<0) {
			pr_emerg("Failed to create command socket at %s\n", command_socket_path);
			return -1;
		}
	}

	pmc = pmc_create(cfg, transport_type, iface_name,
			 config_get_string(cfg, NULL, "uds_address"),
			 boundary_hops, domain_number, transport_specific,
			 allow_unauth, zero_datalen);
	if (!pmc) {
		fprintf(stderr, "failed to create pmc\n");
		config_destroy(cfg);
		return -1;
	}

	// We poll 3 sockets.
	// 0 = active command socket or stdin. In batch mode it is disabled
	// 1 = ptp4l
	// 2 = listening command socket

	pollfd[0].fd = batch_mode ? -1 : STDIN_FILENO;
	pollfd[1].fd = pmc_get_transport_fd(pmc);

	pollfd[2].fd = -1; // disable #2 as default

	if (use_command_socket) {
		// set socket to passive, listening mode
		ret = listen(command_socket_fd, 20);
		if (ret == -1) {
			perror("listen");
			return -1;
		}

		// hang here, waiting for remote
		printf("waiting for remote\n");
		struct sockaddr_un remote;
		socklen_t remote_len;
		remote_fd=accept(command_socket_fd, (struct sockaddr*) &remote, &remote_len);
		if (remote_fd == -1) {
            perror("accept");
			return -1;
		}

		printf("remote connected, fd=%d\n", remote_fd);
		pollfd[0].fd = remote_fd;
		pollfd[2].fd = command_socket_fd;
	}

	while (is_running()) {
		if (batch_mode && !command) {
			if (optind < argc) {
				command = argv[optind++];
			} else {
				/* No more commands, wait a bit for
				   any outstanding replies and exit. */
				tmo = 100;
			}
		}

		pollfd[0].events = 0;
		pollfd[1].events = POLLIN | POLLPRI;
		pollfd[2].events = POLLIN;

		if (!batch_mode && !command)
			pollfd[0].events |= POLLIN | POLLPRI;
		if (command)
			pollfd[1].events |= POLLOUT;

		cnt = poll(pollfd, N_FD, tmo);
		if (cnt < 0) {
			if (EINTR == errno) {
				continue;
			} else {
				pr_emerg("poll failed");
				ret = -1;
				break;
			}
		} else if (!cnt) {
			if (use_command_socket) {
				continue;
			}

			break;
		}
		
		if (pollfd[0].revents & POLLHUP) {
			if (use_command_socket) {
				
				close(STDERR_FILENO);
				// hang here and wait for a new connection
				close(pollfd[0].fd);
				pollfd[0].fd = -1;
				printf("target lost .. searching\n");
				continue;
			}

			if (tmo == -1) {
				/* Wait a bit longer for outstanding replies. */
				tmo = 100;
				pollfd[0].fd = -1;
				pollfd[0].events = 0;
			} else {				
				break;
			}
		}

		if(pollfd[2].revents & POLLIN) {
			struct sockaddr_un remote;
			socklen_t remote_len;
	
			remote_fd=accept(command_socket_fd, (struct sockaddr*) &remote, &remote_len);
			if (remote_fd == -1) {
				perror("accept");
				return -1;
			}

			printf("target reaccquired, fd=%d\n", remote_fd);
			pollfd[0].fd = remote_fd;
		}
		
		if (pollfd[0].revents & (POLLIN|POLLPRI)) {
			if(use_command_socket) {				
				ssize_t size_read = xread(pollfd[0].fd, line, sizeof(line));
				if (size_read < 0) {
					pr_err("read failed\n");
				}
			}
			else {
				if (!fgets(line, sizeof(line), stdin)) {
					break;
				}
			}
			length = strlen(line);
			if (length < 2) {
				continue;
			}
			line[length - 1] = 0;
			command = line;
		}
		if (pollfd[1].revents & POLLOUT) {
			if (pmc_do_command(pmc, command)) {
				fprintf(stderr, "bad command: %s\n", command);
			}
			command = NULL;
		}
		if (pollfd[1].revents & (POLLIN|POLLPRI)) {
			msg = pmc_recv(pmc);
			if (msg) {
				if(use_command_socket) {
					pmc_show(msg, remote_fd);
				}
				else {
					pmc_show(msg, STDOUT_FILENO);
				}

				msg_put(msg);
			}
		}
	}

	pmc_destroy(pmc);
	msg_cleanup();

out:
	sad_destroy(cfg);
	config_destroy(cfg);
	return ret;
}
