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
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "ds.h"
#include "fsm.h"
#include "pmc_common.h"
#include "print.h"
#include "tlv.h"
#include "uds.h"
#include "util.h"
#include "version.h"

#define BAD_ACTION   -1
#define BAD_ID       -1
#define AMBIGUOUS_ID -2
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define P41 ((double)(1ULL << 41))

static struct pmc *pmc;

static void do_get_action(int action, int index, char *str);
static void do_set_action(int action, int index, char *str);
static void not_supported(int action, int index, char *str);
static void null_management(int action, int index, char *str);

struct management_id {
	char name[64];
	int code;
	void (*func)(int action, int index, char *str);
};

struct management_id idtab[] = {
/* Clock management ID values */
	{ "USER_DESCRIPTION", USER_DESCRIPTION, do_get_action },
	{ "SAVE_IN_NON_VOLATILE_STORAGE", SAVE_IN_NON_VOLATILE_STORAGE, not_supported },
	{ "RESET_NON_VOLATILE_STORAGE", RESET_NON_VOLATILE_STORAGE, not_supported },
	{ "INITIALIZE", INITIALIZE, not_supported },
	{ "FAULT_LOG", FAULT_LOG, not_supported },
	{ "FAULT_LOG_RESET", FAULT_LOG_RESET, not_supported },
	{ "DEFAULT_DATA_SET", DEFAULT_DATA_SET, do_get_action },
	{ "CURRENT_DATA_SET", CURRENT_DATA_SET, do_get_action },
	{ "PARENT_DATA_SET", PARENT_DATA_SET, do_get_action },
	{ "TIME_PROPERTIES_DATA_SET", TIME_PROPERTIES_DATA_SET, do_get_action },
	{ "PRIORITY1", PRIORITY1, do_get_action },
	{ "PRIORITY2", PRIORITY2, do_get_action },
	{ "DOMAIN", DOMAIN, do_get_action },
	{ "SLAVE_ONLY", SLAVE_ONLY, do_get_action },
	{ "TIME", TIME, not_supported },
	{ "CLOCK_ACCURACY", CLOCK_ACCURACY, do_get_action },
	{ "UTC_PROPERTIES", UTC_PROPERTIES, not_supported },
	{ "TRACEABILITY_PROPERTIES", TRACEABILITY_PROPERTIES, do_get_action },
	{ "TIMESCALE_PROPERTIES", TIMESCALE_PROPERTIES, do_get_action },
	{ "PATH_TRACE_LIST", PATH_TRACE_LIST, not_supported },
	{ "PATH_TRACE_ENABLE", PATH_TRACE_ENABLE, not_supported },
	{ "GRANDMASTER_CLUSTER_TABLE", GRANDMASTER_CLUSTER_TABLE, not_supported },
	{ "ACCEPTABLE_MASTER_TABLE", ACCEPTABLE_MASTER_TABLE, not_supported },
	{ "ACCEPTABLE_MASTER_MAX_TABLE_SIZE", ACCEPTABLE_MASTER_MAX_TABLE_SIZE, not_supported },
	{ "ALTERNATE_TIME_OFFSET_ENABLE", ALTERNATE_TIME_OFFSET_ENABLE, not_supported },
	{ "ALTERNATE_TIME_OFFSET_NAME", ALTERNATE_TIME_OFFSET_NAME, not_supported },
	{ "ALTERNATE_TIME_OFFSET_MAX_KEY", ALTERNATE_TIME_OFFSET_MAX_KEY, not_supported },
	{ "ALTERNATE_TIME_OFFSET_PROPERTIES", ALTERNATE_TIME_OFFSET_PROPERTIES, not_supported },
	{ "TRANSPARENT_CLOCK_DEFAULT_DATA_SET", TRANSPARENT_CLOCK_DEFAULT_DATA_SET, not_supported },
	{ "PRIMARY_DOMAIN", PRIMARY_DOMAIN, not_supported },
	{ "TIME_STATUS_NP", TIME_STATUS_NP, do_get_action },
	{ "GRANDMASTER_SETTINGS_NP", GRANDMASTER_SETTINGS_NP, do_set_action },
/* Port management ID values */
	{ "NULL_MANAGEMENT", NULL_MANAGEMENT, null_management },
	{ "CLOCK_DESCRIPTION", CLOCK_DESCRIPTION, do_get_action },
	{ "PORT_DATA_SET", PORT_DATA_SET, do_get_action },
	{ "LOG_ANNOUNCE_INTERVAL", LOG_ANNOUNCE_INTERVAL, do_get_action },
	{ "ANNOUNCE_RECEIPT_TIMEOUT", ANNOUNCE_RECEIPT_TIMEOUT, do_get_action },
	{ "LOG_SYNC_INTERVAL", LOG_SYNC_INTERVAL, do_get_action },
	{ "VERSION_NUMBER", VERSION_NUMBER, do_get_action },
	{ "ENABLE_PORT", ENABLE_PORT, not_supported },
	{ "DISABLE_PORT", DISABLE_PORT, not_supported },
	{ "UNICAST_NEGOTIATION_ENABLE", UNICAST_NEGOTIATION_ENABLE, not_supported },
	{ "UNICAST_MASTER_TABLE", UNICAST_MASTER_TABLE, not_supported },
	{ "UNICAST_MASTER_MAX_TABLE_SIZE", UNICAST_MASTER_MAX_TABLE_SIZE, not_supported },
	{ "ACCEPTABLE_MASTER_TABLE_ENABLED", ACCEPTABLE_MASTER_TABLE_ENABLED, not_supported },
	{ "ALTERNATE_MASTER", ALTERNATE_MASTER, not_supported },
	{ "TRANSPARENT_CLOCK_PORT_DATA_SET", TRANSPARENT_CLOCK_PORT_DATA_SET, not_supported },
	{ "DELAY_MECHANISM", DELAY_MECHANISM, do_get_action },
	{ "LOG_MIN_PDELAY_REQ_INTERVAL", LOG_MIN_PDELAY_REQ_INTERVAL, do_get_action },
};

static char *action_string[] = {
	"GET",
	"SET",
	"RESPONSE",
	"COMMAND",
	"ACKNOWLEDGE",
};

#define IFMT "\n\t\t"

static char *text2str(struct PTPText *text)
{
	static struct static_ptp_text s;
	s.max_symbols = -1;
	static_ptp_text_copy(&s, text);
	return (char*)(s.text);
}

#define MAX_PRINT_BYTES 16
#define BIN_BUF_SIZE (MAX_PRINT_BYTES * 3 + 1)

static char *bin2str_impl(Octet *data, int len, char *buf, int buf_len)
{
	int i, offset = 0;
	if (len > MAX_PRINT_BYTES)
		len = MAX_PRINT_BYTES;
	buf[0] = '\0';
	if (!data)
		return buf;
	if (len)
		offset += snprintf(buf, buf_len, "%02hhx", data[0]);
	for (i = 1; i < len; i++) {
		if (offset >= buf_len)
			/* truncated output */
			break;
		offset += snprintf(buf + offset, buf_len - offset, ":%02hhx", data[i]);
	}
	return buf;
}

static char *bin2str(Octet *data, int len)
{
	static char buf[BIN_BUF_SIZE];
	return bin2str_impl(data, len, buf, sizeof(buf));
}

static uint16_t align16(uint16_t *p)
{
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static char *portaddr2str(struct PortAddress *addr)
{
	static char buf[BIN_BUF_SIZE];
	switch(align16(&addr->networkProtocol)) {
	case TRANS_UDP_IPV4:
		if (align16(&addr->addressLength) == 4
			&& inet_ntop(AF_INET, addr->address, buf, sizeof(buf)))
			return buf;
		break;
	case TRANS_UDP_IPV6:
		if (align16(&addr->addressLength) == 16
			&& inet_ntop(AF_INET6, addr->address, buf, sizeof(buf)))
			return buf;
		break;
	}
	bin2str_impl(addr->address, align16(&addr->addressLength), buf, sizeof(buf));
	return buf;
}

static void pmc_show(struct ptp_message *msg, FILE *fp)
{
	int action;
	struct TLV *tlv;
	struct management_tlv *mgt;
	struct management_tlv_datum *mtd;
	struct defaultDS *dds;
	struct currentDS *cds;
	struct parentDS *pds;
	struct timePropertiesDS *tp;
	struct time_status_np *tsn;
	struct grandmaster_settings_np *gsn;
	struct mgmt_clock_description *cd;
	struct portDS *p;
	if (msg_type(msg) != MANAGEMENT) {
		return;
	}
	action = management_action(msg);
	if (action < GET || action > ACKNOWLEDGE) {
		return;
	}
	fprintf(fp, "\t%s seq %hu %s ",
		pid2str(&msg->header.sourcePortIdentity),
		msg->header.sequenceId, action_string[action]);
	if (msg->tlv_count != 1) {
		goto out;
	}
	tlv = (struct TLV *) msg->management.suffix;
	if (tlv->type == TLV_MANAGEMENT) {
		fprintf(fp, "MANAGMENT ");
	} else if (tlv->type == TLV_MANAGEMENT_ERROR_STATUS) {
		fprintf(fp, "MANAGMENT_ERROR_STATUS ");
		goto out;
	} else {
		fprintf(fp, "unknown-tlv ");
	}
	mgt = (struct management_tlv *) msg->management.suffix;
	if (mgt->length == 2 && mgt->id != NULL_MANAGEMENT) {
		fprintf(fp, "empty-tlv ");
		goto out;
	}
	switch (mgt->id) {
	case CLOCK_DESCRIPTION:
		cd = &msg->last_tlv.cd;
		fprintf(fp, "CLOCK_DESCRIPTION "
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
		fprintf(fp, IFMT "manufacturerId        %s"
                        IFMT "productDescription    %s",
			bin2str(cd->manufacturerIdentity, OUI_LEN),
			text2str(cd->productDescription));
		fprintf(fp, IFMT "revisionData          %s",
                        text2str(cd->revisionData));
		fprintf(fp, IFMT "userDescription       %s"
                        IFMT "profileId             %s",
			text2str(cd->userDescription),
			bin2str(cd->profileIdentity, PROFILE_ID_LEN));
		break;
	case USER_DESCRIPTION:
		fprintf(fp, "USER_DESCRIPTION "
			IFMT "userDescription  %s",
			text2str(msg->last_tlv.cd.userDescription));
		break;
	case DEFAULT_DATA_SET:
		dds = (struct defaultDS *) mgt->data;
		fprintf(fp, "DEFAULT_DATA_SET "
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
	case CURRENT_DATA_SET:
		cds = (struct currentDS *) mgt->data;
		fprintf(fp, "CURRENT_DATA_SET "
			IFMT "stepsRemoved     %hd"
			IFMT "offsetFromMaster %.1f"
			IFMT "meanPathDelay    %.1f",
			cds->stepsRemoved, cds->offsetFromMaster / 65536.0,
			cds->meanPathDelay / 65536.0);
		break;
	case PARENT_DATA_SET:
		pds = (struct parentDS *) mgt->data;
		fprintf(fp, "PARENT_DATA_SET "
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
	case TIME_PROPERTIES_DATA_SET:
		tp = (struct timePropertiesDS *) mgt->data;
		fprintf(fp, "TIME_PROPERTIES_DATA_SET "
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
	case PRIORITY1:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "PRIORITY1 "
			IFMT "priority1 %hhu", mtd->val);
		break;
	case PRIORITY2:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "PRIORITY2 "
			IFMT "priority2 %hhu", mtd->val);
		break;
	case DOMAIN:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "DOMAIN "
			IFMT "domainNumber %hhu", mtd->val);
		break;
	case SLAVE_ONLY:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "SLAVE_ONLY "
			IFMT "slaveOnly %d", mtd->val & DDS_SLAVE_ONLY ? 1 : 0);
		break;
	case CLOCK_ACCURACY:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "CLOCK_ACCURACY "
			IFMT "clockAccuracy 0x%02hhx", mtd->val);
		break;
	case TRACEABILITY_PROPERTIES:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "TRACEABILITY_PROPERTIES "
			IFMT "timeTraceable      %d"
			IFMT "frequencyTraceable %d",
			mtd->val & TIME_TRACEABLE ? 1 : 0,
			mtd->val & FREQ_TRACEABLE ? 1 : 0);
		break;
	case TIMESCALE_PROPERTIES:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "TIMESCALE_PROPERTIES "
			IFMT "ptpTimescale %d", mtd->val & PTP_TIMESCALE ? 1 : 0);
		break;
	case TIME_STATUS_NP:
		tsn = (struct time_status_np *) mgt->data;
		fprintf(fp, "TIME_STATUS_NP "
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
			1.0 + (tsn->cumulativeScaledRateOffset + 0.0) / P41,
			tsn->scaledLastGmPhaseChange,
			tsn->gmTimeBaseIndicator,
			tsn->lastGmPhaseChange.nanoseconds_msb,
			tsn->lastGmPhaseChange.nanoseconds_lsb,
			tsn->lastGmPhaseChange.fractional_nanoseconds,
			tsn->gmPresent ? "true" : "false",
			cid2str(&tsn->gmIdentity));
		break;
	case GRANDMASTER_SETTINGS_NP:
		gsn = (struct grandmaster_settings_np *) mgt->data;
		fprintf(fp, "GRANDMASTER_SETTINGS_NP "
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
	case PORT_DATA_SET:
		p = (struct portDS *) mgt->data;
		if (p->portState > PS_SLAVE) {
			p->portState = 0;
		}
		fprintf(fp, "PORT_DATA_SET "
			IFMT "portIdentity            %s"
			IFMT "portState               %s"
			IFMT "logMinDelayReqInterval  %hhd"
			IFMT "peerMeanPathDelay       %" PRId64
			IFMT "logAnnounceInterval     %hhd"
			IFMT "announceReceiptTimeout  %hhu"
			IFMT "logSyncInterval         %hhd"
			IFMT "delayMechanism          %hhu"
			IFMT "logMinPdelayReqInterval %hhd"
			IFMT "versionNumber           %hhu",
			pid2str(&p->portIdentity), ps_str[p->portState],
			p->logMinDelayReqInterval, p->peerMeanPathDelay >> 16,
			p->logAnnounceInterval, p->announceReceiptTimeout,
			p->logSyncInterval, p->delayMechanism,
			p->logMinPdelayReqInterval, p->versionNumber);
		break;
	case LOG_ANNOUNCE_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "LOG_ANNOUNCE_INTERVAL "
			IFMT "logAnnounceInterval %hhd", mtd->val);
		break;
	case ANNOUNCE_RECEIPT_TIMEOUT:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "ANNOUNCE_RECEIPT_TIMEOUT "
			IFMT "announceReceiptTimeout %hhu", mtd->val);
		break;
	case LOG_SYNC_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "ANNOUNCE_RECEIPT_TIMEOUT "
			IFMT "logSyncInterval %hhd", mtd->val);
		break;
	case VERSION_NUMBER:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "VERSION_NUMBER "
			IFMT "versionNumber %hhu", mtd->val);
		break;
	case DELAY_MECHANISM:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "DELAY_MECHANISM "
			IFMT "delayMechanism %hhu", mtd->val);
		break;
	case LOG_MIN_PDELAY_REQ_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "LOG_MIN_PDELAY_REQ_INTERVAL "
			IFMT "logMinPdelayReqInterval %hhd", mtd->val);
		break;
	}
out:
	fprintf(fp, "\n");
	fflush(fp);
}

static void do_get_action(int action, int index, char *str)
{
	if (action == GET)
		pmc_send_get_action(pmc, idtab[index].code);
	else
		fprintf(stderr, "%s only allows GET\n", idtab[index].name);
}

static void do_set_action(int action, int index, char *str)
{
	struct grandmaster_settings_np gsn;
	int cnt, code = idtab[index].code;
	int leap_61, leap_59, utc_off_valid;
	int ptp_timescale, time_traceable, freq_traceable;

	switch (action) {
	case GET:
		pmc_send_get_action(pmc, code);
		return;
	case SET:
		break;
	case RESPONSE:
	case COMMAND:
	case ACKNOWLEDGE:
	default:
		fprintf(stderr, "%s only allows GET or SET\n",
			idtab[index].name);
		return;
	}
	switch (code) {
	case GRANDMASTER_SETTINGS_NP:
		cnt = sscanf(str, " %*s %*s "
			     "clockClass              %hhu "
			     "clockAccuracy           %hhx "
			     "offsetScaledLogVariance %hx "
			     "currentUtcOffset        %hd "
			     "leap61                  %d "
			     "leap59                  %d "
			     "currentUtcOffsetValid   %d "
			     "ptpTimescale            %d "
			     "timeTraceable           %d "
			     "frequencyTraceable      %d "
			     "timeSource              %hhx ",
			     &gsn.clockQuality.clockClass,
			     &gsn.clockQuality.clockAccuracy,
			     &gsn.clockQuality.offsetScaledLogVariance,
			     &gsn.utc_offset,
			     &leap_61,
			     &leap_59,
			     &utc_off_valid,
			     &ptp_timescale,
			     &time_traceable,
			     &freq_traceable,
			     &gsn.time_source);
		if (cnt != 11) {
			fprintf(stderr, "%s SET needs 11 values\n",
				idtab[index].name);
			break;
		}
		gsn.time_flags = 0;
		if (leap_61)
			gsn.time_flags |= LEAP_61;
		if (leap_59)
			gsn.time_flags |= LEAP_59;
		if (utc_off_valid)
			gsn.time_flags |= UTC_OFF_VALID;
		if (ptp_timescale)
			gsn.time_flags |= PTP_TIMESCALE;
		if (time_traceable)
			gsn.time_flags |= TIME_TRACEABLE;
		if (freq_traceable)
			gsn.time_flags |= FREQ_TRACEABLE;
		pmc_send_set_action(pmc, code, &gsn, sizeof(gsn));
		break;
	}
}

static void not_supported(int action, int index, char *str)
{
	fprintf(stdout, "sorry, %s not supported yet\n", idtab[index].name);
}

static void null_management(int action, int index, char *str)
{
	if (action == GET)
		pmc_send_get_action(pmc, idtab[index].code);
	else
		puts("non-get actions still todo");
}

static int parse_action(char *s)
{
	int len = strlen(s);
	if (0 == strncasecmp(s, "GET", len))
		return GET;
	else if (0 == strncasecmp(s, "SET", len))
		return SET;
	else if (0 == strncasecmp(s, "CMD", len))
		return COMMAND;
	else if (0 == strncasecmp(s, "COMMAND", len))
		return COMMAND;
	return BAD_ACTION;
}

static int parse_id(char *s)
{
	int i, index = BAD_ID, len = strlen(s);
	/* check for exact match */
	for (i = 0; i < ARRAY_SIZE(idtab); i++) {
		if (strcasecmp(s, idtab[i].name) == 0) {
			return i;
		}
	}
	/* look for a unique prefix match */
	for (i = 0; i < ARRAY_SIZE(idtab); i++) {
		if (0 == strncasecmp(s, idtab[i].name, len)) {
			if (index == BAD_ID)
				index = i;
			else
				return AMBIGUOUS_ID;
		}
	}
	return index;
}

static int parse_target(const char *str)
{
	struct PortIdentity pid;

	if (str[0] == '*') {
		memset(&pid, 0xff, sizeof(pid));
	} else if (str2pid(str, &pid)) {
		return -1;
	}

	return pmc_target(pmc, &pid);
}

static void print_help(FILE *fp)
{
	int i;
	fprintf(fp, "\n");
	for (i = 0; i < ARRAY_SIZE(idtab); i++) {
		if (idtab[i].func != not_supported)
			fprintf(fp, "\t[action] %s\n", idtab[i].name);
	}
	fprintf(fp, "\n");
	fprintf(fp, "\tThe [action] can be GET, SET, CMD, or COMMAND\n");
	fprintf(fp, "\tCommands are case insensitive and may be abbreviated.\n");
	fprintf(fp, "\n");
	fprintf(fp, "\tTARGET [portIdentity]\n");
	fprintf(fp, "\tTARGET *\n");
	fprintf(fp, "\n");
}

static int do_command(char *str)
{
	int action, id;
	char action_str[10+1] = {0}, id_str[64+1] = {0};

	if (0 == strncasecmp(str, "HELP", strlen(str))) {
		print_help(stdout);
		return 0;
	}

	if (2 != sscanf(str, " %10s %64s", action_str, id_str))
		return -1;

	if (0 == strncasecmp(action_str, "TARGET", strlen(action_str)))
		return parse_target(id_str);

	action = parse_action(action_str);
	id = parse_id(id_str);

	if (action == BAD_ACTION || id == BAD_ID)
		return -1;

	if (id == AMBIGUOUS_ID) {
		fprintf(stdout, "id %s is too ambiguous\n", id_str);
		return 0;
	}

	fprintf(stdout, "sending: %s %s\n",
		action_string[action], idtab[id].name);

	idtab[id].func(action, id, str);

	return 0;
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
		" -d [num]  domain number, default 0\n"
		" -h        prints this message and exits\n"
		" -i [dev]  interface device to use, default 'eth0'\n"
		"           for network and '/var/run/pmc' for UDS.\n"
		" -s [path] server address for UDS, default '/var/run/ptp4l'.\n"
		" -t [hex]  transport specific field, default 0x0\n"
		" -v        prints the software version and exits\n"
		" -z        send zero length TLV values with the GET actions\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *iface_name = NULL, *progname;
	int c, cnt, length, tmo = -1, batch_mode = 0, zero_datalen = 0;
	char line[1024], *command = NULL;
	enum transport_type transport_type = TRANS_UDP_IPV4;
	UInteger8 boundary_hops = 1, domain_number = 0, transport_specific = 0;
	struct ptp_message *msg;
#define N_FD 2
	struct pollfd pollfd[N_FD];

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "246u""b:d:hi:s:t:vz"))) {
		switch (c) {
		case '2':
			transport_type = TRANS_IEEE_802_3;
			break;
		case '4':
			transport_type = TRANS_UDP_IPV4;
			break;
		case '6':
			transport_type = TRANS_UDP_IPV6;
			break;
		case 'u':
			transport_type = TRANS_UDS;
			break;
		case 'b':
			boundary_hops = atoi(optarg);
			break;
		case 'd':
			domain_number = atoi(optarg);
			break;
		case 'i':
			iface_name = optarg;
			break;
		case 's':
			if (strlen(optarg) > MAX_IFNAME_SIZE) {
				fprintf(stderr, "path %s too long, max is %d\n",
					optarg, MAX_IFNAME_SIZE);
				return -1;
			}
			strncpy(uds_path, optarg, MAX_IFNAME_SIZE);
			break;
		case 't':
			if (1 == sscanf(optarg, "%x", &c))
				transport_specific = c << 4;
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'z':
			zero_datalen = 1;
			break;
		case 'h':
			usage(progname);
			return 0;
		case '?':
			usage(progname);
			return -1;
		default:
			usage(progname);
			return -1;
		}
	}

	if (!iface_name) {
		iface_name = transport_type == TRANS_UDS ? "/var/run/pmc" : "eth0";
	}
	if (optind < argc) {
		batch_mode = 1;
	}

	print_set_progname(progname);
	print_set_syslog(1);
	print_set_verbose(1);

	pmc = pmc_create(transport_type, iface_name, boundary_hops,
			 domain_number, transport_specific, zero_datalen);
	if (!pmc) {
		fprintf(stderr, "failed to create pmc\n");
		return -1;
	}

	pollfd[0].fd = batch_mode ? -1 : STDIN_FILENO;
	pollfd[1].fd = pmc_get_transport_fd(pmc);

	while (1) {
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
				return -1;
			}
		} else if (!cnt) {
			break;
		}
		if (pollfd[0].revents & POLLHUP) {
			if (tmo == -1) {
				/* Wait a bit longer for outstanding replies. */
				tmo = 100;
				pollfd[0].fd = -1;
				pollfd[0].events = 0;
			} else {
				break;
			}
		}
		if (pollfd[0].revents & (POLLIN|POLLPRI)) {
			if (!fgets(line, sizeof(line), stdin)) {
				break;
			}
			length = strlen(line);
			if (length < 2) {
				continue;
			}
			line[length - 1] = 0;
			command = line;
		}
		if (pollfd[1].revents & POLLOUT) {
			if (do_command(command)) {
				fprintf(stderr, "bad command: %s\n", command);
			}
			command = NULL;
		}
		if (pollfd[1].revents & (POLLIN|POLLPRI)) {
			msg = pmc_recv(pmc);
			if (msg) {
				pmc_show(msg, stdout);
				msg_put(msg);
			}
		}
	}

	pmc_destroy(pmc);
	msg_cleanup();
	return 0;
}
