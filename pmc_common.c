/**
 * @file pmc_common.c
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note Copyright (C) 2013 Miroslav Lichvar <mlichvar@redhat.com>
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
#include <string.h>
#include <stdlib.h>

#include "print.h"
#include "tlv.h"
#include "transport.h"
#include "util.h"
#include "pmc_common.h"

/*
   Field                  Len  Type
  --------------------------------------------------------
   clockType                2
   physicalLayerProtocol    1  PTPText
   physicalAddressLength    2  UInteger16
   physicalAddress          0
   protocolAddress          4  Enumeration16 + UInteger16
   manufacturerIdentity     3
   reserved                 1
   productDescription       1  PTPText
   revisionData             1  PTPText
   userDescription          1  PTPText
   profileIdentity          6
  --------------------------------------------------------
   TOTAL                   22
*/
#define EMPTY_CLOCK_DESCRIPTION 22
/* Includes one extra byte to make length even. */
#define EMPTY_PTP_TEXT 2

static void do_get_action(struct pmc *pmc, int action, int index, char *str);
static void do_set_action(struct pmc *pmc, int action, int index, char *str);
static void not_supported(struct pmc *pmc, int action, int index, char *str);
static void null_management(struct pmc *pmc, int action, int index, char *str);

static const char *action_string[] = {
	"GET",
	"SET",
	"RESPONSE",
	"COMMAND",
	"ACKNOWLEDGE",
};

struct management_id {
	char name[64];
	int code;
	void (*func)(struct pmc *pmc, int action, int index, char *str);
};

struct management_id idtab[] = {
/* Clock management ID values */
	{ "USER_DESCRIPTION", TLV_USER_DESCRIPTION, do_get_action },
	{ "SAVE_IN_NON_VOLATILE_STORAGE", TLV_SAVE_IN_NON_VOLATILE_STORAGE, not_supported },
	{ "RESET_NON_VOLATILE_STORAGE", TLV_RESET_NON_VOLATILE_STORAGE, not_supported },
	{ "INITIALIZE", TLV_INITIALIZE, not_supported },
	{ "FAULT_LOG", TLV_FAULT_LOG, not_supported },
	{ "FAULT_LOG_RESET", TLV_FAULT_LOG_RESET, not_supported },
	{ "DEFAULT_DATA_SET", TLV_DEFAULT_DATA_SET, do_get_action },
	{ "CURRENT_DATA_SET", TLV_CURRENT_DATA_SET, do_get_action },
	{ "PARENT_DATA_SET", TLV_PARENT_DATA_SET, do_get_action },
	{ "TIME_PROPERTIES_DATA_SET", TLV_TIME_PROPERTIES_DATA_SET, do_get_action },
	{ "PRIORITY1", TLV_PRIORITY1, do_set_action },
	{ "PRIORITY2", TLV_PRIORITY2, do_set_action },
	{ "DOMAIN", TLV_DOMAIN, do_get_action },
	{ "SLAVE_ONLY", TLV_SLAVE_ONLY, do_get_action },
	{ "TIME", TLV_TIME, not_supported },
	{ "CLOCK_ACCURACY", TLV_CLOCK_ACCURACY, do_get_action },
	{ "UTC_PROPERTIES", TLV_UTC_PROPERTIES, not_supported },
	{ "TRACEABILITY_PROPERTIES", TLV_TRACEABILITY_PROPERTIES, do_get_action },
	{ "TIMESCALE_PROPERTIES", TLV_TIMESCALE_PROPERTIES, do_get_action },
	{ "PATH_TRACE_LIST", TLV_PATH_TRACE_LIST, not_supported },
	{ "PATH_TRACE_ENABLE", TLV_PATH_TRACE_ENABLE, not_supported },
	{ "GRANDMASTER_CLUSTER_TABLE", TLV_GRANDMASTER_CLUSTER_TABLE, not_supported },
	{ "ACCEPTABLE_MASTER_TABLE", TLV_ACCEPTABLE_MASTER_TABLE, not_supported },
	{ "ACCEPTABLE_MASTER_MAX_TABLE_SIZE", TLV_ACCEPTABLE_MASTER_MAX_TABLE_SIZE, not_supported },
	{ "ALTERNATE_TIME_OFFSET_ENABLE", TLV_ALTERNATE_TIME_OFFSET_ENABLE, not_supported },
	{ "ALTERNATE_TIME_OFFSET_NAME", TLV_ALTERNATE_TIME_OFFSET_NAME, not_supported },
	{ "ALTERNATE_TIME_OFFSET_MAX_KEY", TLV_ALTERNATE_TIME_OFFSET_MAX_KEY, not_supported },
	{ "ALTERNATE_TIME_OFFSET_PROPERTIES", TLV_ALTERNATE_TIME_OFFSET_PROPERTIES, not_supported },
	{ "TRANSPARENT_CLOCK_DEFAULT_DATA_SET", TLV_TRANSPARENT_CLOCK_DEFAULT_DATA_SET, not_supported },
	{ "PRIMARY_DOMAIN", TLV_PRIMARY_DOMAIN, not_supported },
	{ "TIME_STATUS_NP", TLV_TIME_STATUS_NP, do_get_action },
	{ "GRANDMASTER_SETTINGS_NP", TLV_GRANDMASTER_SETTINGS_NP, do_set_action },
/* Port management ID values */
	{ "NULL_MANAGEMENT", TLV_NULL_MANAGEMENT, null_management },
	{ "CLOCK_DESCRIPTION", TLV_CLOCK_DESCRIPTION, do_get_action },
	{ "PORT_DATA_SET", TLV_PORT_DATA_SET, do_get_action },
	{ "LOG_ANNOUNCE_INTERVAL", TLV_LOG_ANNOUNCE_INTERVAL, do_get_action },
	{ "ANNOUNCE_RECEIPT_TIMEOUT", TLV_ANNOUNCE_RECEIPT_TIMEOUT, do_get_action },
	{ "LOG_SYNC_INTERVAL", TLV_LOG_SYNC_INTERVAL, do_get_action },
	{ "VERSION_NUMBER", TLV_VERSION_NUMBER, do_get_action },
	{ "ENABLE_PORT", TLV_ENABLE_PORT, not_supported },
	{ "DISABLE_PORT", TLV_DISABLE_PORT, not_supported },
	{ "UNICAST_NEGOTIATION_ENABLE", TLV_UNICAST_NEGOTIATION_ENABLE, not_supported },
	{ "UNICAST_MASTER_TABLE", TLV_UNICAST_MASTER_TABLE, not_supported },
	{ "UNICAST_MASTER_MAX_TABLE_SIZE", TLV_UNICAST_MASTER_MAX_TABLE_SIZE, not_supported },
	{ "ACCEPTABLE_MASTER_TABLE_ENABLED", TLV_ACCEPTABLE_MASTER_TABLE_ENABLED, not_supported },
	{ "ALTERNATE_MASTER", TLV_ALTERNATE_MASTER, not_supported },
	{ "TRANSPARENT_CLOCK_PORT_DATA_SET", TLV_TRANSPARENT_CLOCK_PORT_DATA_SET, not_supported },
	{ "DELAY_MECHANISM", TLV_DELAY_MECHANISM, do_get_action },
	{ "LOG_MIN_PDELAY_REQ_INTERVAL", TLV_LOG_MIN_PDELAY_REQ_INTERVAL, do_get_action },
	{ "PORT_DATA_SET_NP", TLV_PORT_DATA_SET_NP, do_set_action },
};

static void do_get_action(struct pmc *pmc, int action, int index, char *str)
{
	if (action == GET)
		pmc_send_get_action(pmc, idtab[index].code);
	else
		fprintf(stderr, "%s only allows GET\n", idtab[index].name);
}

static void do_set_action(struct pmc *pmc, int action, int index, char *str)
{
	struct grandmaster_settings_np gsn;
	struct management_tlv_datum mtd;
	struct port_ds_np pnp;
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
	case TLV_PRIORITY1:
	case TLV_PRIORITY2:
		cnt = sscanf(str,  " %*s %*s %hhu", &mtd.val);
		if (cnt != 1) {
			fprintf(stderr, "%s SET needs 1 value\n",
				idtab[index].name);
			break;
		}
		pmc_send_set_action(pmc, code, &mtd, sizeof(mtd));
		break;
	case TLV_GRANDMASTER_SETTINGS_NP:
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
	case TLV_PORT_DATA_SET_NP:
		cnt = sscanf(str, " %*s %*s "
			     "neighborPropDelayThresh %u "
			     "asCapable               %d ",
			     &pnp.neighborPropDelayThresh,
			     &pnp.asCapable);
		if (cnt != 2) {
			fprintf(stderr, "%s SET needs 2 values\n",
				idtab[index].name);
			break;
		}
		pmc_send_set_action(pmc, code, &pnp, sizeof(pnp));
		break;
	}
}

static void not_supported(struct pmc *pmc, int action, int index, char *str)
{
	fprintf(stdout, "sorry, %s not supported yet\n", idtab[index].name);
}

static void null_management(struct pmc *pmc, int action, int index, char *str)
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

static int parse_target(struct pmc *pmc, const char *str)
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

struct pmc {
	UInteger16 sequence_id;
	UInteger8 boundary_hops;
	UInteger8 domain_number;
	UInteger8 transport_specific;
	struct PortIdentity port_identity;
	struct PortIdentity target;

	struct transport *transport;
	struct fdarray fdarray;
	int zero_length_gets;
};

struct pmc *pmc_create(struct config *cfg, enum transport_type transport_type,
		       const char *iface_name, UInteger8 boundary_hops,
		       UInteger8 domain_number, UInteger8 transport_specific,
		       int zero_datalen)
{
	struct interface iface;
	struct pmc *pmc;

	memset(&iface, 0, sizeof(iface));

	pmc = calloc(1, sizeof *pmc);
	if (!pmc)
		return NULL;

	if (transport_type != TRANS_UDS &&
	    generate_clock_identity(&pmc->port_identity.clockIdentity,
				    iface_name)) {
		pr_err("failed to generate a clock identity");
		goto failed;
	}
	pmc->port_identity.portNumber = 1;
	pmc_target_all(pmc);

	pmc->boundary_hops = boundary_hops;
	pmc->domain_number = domain_number;
	pmc->transport_specific = transport_specific;

	pmc->transport = transport_create(cfg, transport_type);
	if (!pmc->transport) {
		pr_err("failed to create transport");
		goto failed;
	}

	strncpy(iface.name, iface_name, MAX_IFNAME_SIZE);
	if (iface.ts_label[0] == '\0') {
		strncpy(iface.ts_label, iface.name, MAX_IFNAME_SIZE);
	}

	if (transport_open(pmc->transport, &iface,
			   &pmc->fdarray, TS_SOFTWARE)) {
		pr_err("failed to open transport");
		goto failed;
	}
	pmc->zero_length_gets = zero_datalen ? 1 : 0;

	return pmc;

failed:
	if (pmc->transport)
		transport_destroy(pmc->transport);
	free(pmc);
	return NULL;
}

void pmc_destroy(struct pmc *pmc)
{
	transport_close(pmc->transport, &pmc->fdarray);
	transport_destroy(pmc->transport);
	free(pmc);
}

static struct ptp_message *pmc_message(struct pmc *pmc, uint8_t action)
{
	struct ptp_message *msg;
	int pdulen;

	msg = msg_allocate();
	if (!msg)
		return NULL;

	pdulen = sizeof(struct management_msg);
	msg->hwts.type = TS_SOFTWARE;

	msg->header.tsmt               = MANAGEMENT | pmc->transport_specific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = pmc->domain_number;
	msg->header.sourcePortIdentity = pmc->port_identity;
	msg->header.sequenceId         = pmc->sequence_id++;
	msg->header.control            = CTL_MANAGEMENT;
	msg->header.logMessageInterval = 0x7f;

	msg->management.targetPortIdentity = pmc->target;
	msg->management.startingBoundaryHops = pmc->boundary_hops;
	msg->management.boundaryHops = pmc->boundary_hops;
	msg->management.flags = action;

	return msg;
}

static int pmc_send(struct pmc *pmc, struct ptp_message *msg)
{
	int err;

	err = msg_pre_send(msg);
	if (err) {
		pr_err("msg_pre_send failed");
		return -1;
	}
	return transport_send(pmc->transport, &pmc->fdarray,
			      TRANS_GENERAL, msg);
}

static int pmc_tlv_datalen(struct pmc *pmc, int id)
{
	int len = 0;

	if (pmc->zero_length_gets)
		return len;

	switch (id) {
	case TLV_USER_DESCRIPTION:
		len += EMPTY_PTP_TEXT;
		break;
	case TLV_DEFAULT_DATA_SET:
		len += sizeof(struct defaultDS);
		break;
	case TLV_CURRENT_DATA_SET:
		len += sizeof(struct currentDS);
		break;
	case TLV_PARENT_DATA_SET:
		len += sizeof(struct parentDS);
		break;
	case TLV_TIME_PROPERTIES_DATA_SET:
		len += sizeof(struct timePropertiesDS);
		break;
	case TLV_PRIORITY1:
	case TLV_PRIORITY2:
	case TLV_DOMAIN:
	case TLV_SLAVE_ONLY:
	case TLV_CLOCK_ACCURACY:
	case TLV_TRACEABILITY_PROPERTIES:
	case TLV_TIMESCALE_PROPERTIES:
		len += sizeof(struct management_tlv_datum);
		break;
	case TLV_TIME_STATUS_NP:
		len += sizeof(struct time_status_np);
		break;
	case TLV_GRANDMASTER_SETTINGS_NP:
		len += sizeof(struct grandmaster_settings_np);
		break;
	case TLV_NULL_MANAGEMENT:
		break;
	case TLV_CLOCK_DESCRIPTION:
		len += EMPTY_CLOCK_DESCRIPTION;
		break;
	case TLV_PORT_DATA_SET:
		len += sizeof(struct portDS);
		break;
	case TLV_PORT_DATA_SET_NP:
		len += sizeof(struct port_ds_np);
		break;
	case TLV_LOG_ANNOUNCE_INTERVAL:
	case TLV_ANNOUNCE_RECEIPT_TIMEOUT:
	case TLV_LOG_SYNC_INTERVAL:
	case TLV_VERSION_NUMBER:
	case TLV_DELAY_MECHANISM:
	case TLV_LOG_MIN_PDELAY_REQ_INTERVAL:
		len += sizeof(struct management_tlv_datum);
		break;
	}
	return len;
}

int pmc_get_transport_fd(struct pmc *pmc)
{
	return pmc->fdarray.fd[FD_GENERAL];
}

int pmc_send_get_action(struct pmc *pmc, int id)
{
	int datalen, pdulen;
	struct ptp_message *msg;
	struct management_tlv *mgt;
	struct tlv_extra *extra;

	msg = pmc_message(pmc, GET);
	if (!msg) {
		return -1;
	}
	mgt = (struct management_tlv *) msg->management.suffix;
	mgt->type = TLV_MANAGEMENT;
	datalen = pmc_tlv_datalen(pmc, id);
	mgt->length = 2 + datalen;
	mgt->id = id;
	pdulen = msg->header.messageLength + sizeof(*mgt) + datalen;
	msg->header.messageLength = pdulen;

	extra = tlv_extra_alloc();
	if (!extra) {
		pr_err("failed to allocate TLV descriptor");
		msg_put(msg);
		return -ENOMEM;
	}
	extra->tlv = (struct TLV *) msg->management.suffix;
	msg_tlv_attach(msg, extra);

	if (id == TLV_CLOCK_DESCRIPTION && !pmc->zero_length_gets) {
		/*
		 * Make sure the tlv_extra pointers dereferenced in
		 * mgt_pre_send() do point to something.
		 */
		struct mgmt_clock_description *cd = &extra->cd;
		uint8_t *buf = mgt->data;
		cd->clockType = (UInteger16 *) buf;
		buf += sizeof(*cd->clockType);
		cd->physicalLayerProtocol = (struct PTPText *) buf;
		buf += sizeof(struct PTPText) + cd->physicalLayerProtocol->length;
		cd->physicalAddress = (struct PhysicalAddress *) buf;
		buf += sizeof(struct PhysicalAddress) + 0;
		cd->protocolAddress = (struct PortAddress *) buf;
	}

	pmc_send(pmc, msg);
	msg_put(msg);

	return 0;
}

int pmc_send_set_action(struct pmc *pmc, int id, void *data, int datasize)
{
	struct management_tlv *mgt;
	struct ptp_message *msg;
	struct tlv_extra *extra;

	msg = pmc_message(pmc, SET);
	if (!msg) {
		return -1;
	}
	extra = msg_tlv_append(msg, sizeof(*mgt) + datasize);
	if (!extra) {
		return -ENOMEM;
	}
	mgt = (struct management_tlv *) extra->tlv;
	mgt->type = TLV_MANAGEMENT;
	mgt->length = 2 + datasize;
	mgt->id = id;
	memcpy(mgt->data, data, datasize);
	pmc_send(pmc, msg);
	msg_put(msg);

	return 0;
}

struct ptp_message *pmc_recv(struct pmc *pmc)
{
	struct ptp_message *msg;
	int cnt, err;

	msg = msg_allocate();
	if (!msg) {
		pr_err("low memory");
		return NULL;
	}
	msg->hwts.type = TS_SOFTWARE;
	cnt = transport_recv(pmc->transport, pmc_get_transport_fd(pmc), msg);
	if (cnt <= 0) {
		pr_err("recv message failed");
		goto failed;
	}
	err = msg_post_recv(msg, cnt);
	if (err) {
		switch (err) {
		case -EBADMSG:
			pr_err("bad message");
			break;
		case -EPROTO:
			pr_debug("ignoring message");
			break;
		}
		goto failed;
	}
	if (msg_sots_missing(msg)) {
		pr_err("received %s without timestamp",
		       msg_type_string(msg_type(msg)));
		goto failed;
	}

	return msg;
failed:
	msg_put(msg);
	return NULL;
}

int pmc_target(struct pmc *pmc, struct PortIdentity *pid)
{
	pmc->target = *pid;
	return 0;
}

void pmc_target_port(struct pmc *pmc, UInteger16 portNumber)
{
	pmc->target.portNumber = portNumber;
}

void pmc_target_all(struct pmc *pmc)
{
	memset(&pmc->target, 0xff, sizeof(pmc->target));
}

const char *pmc_action_string(int action)
{
	return action_string[action];
}

int pmc_do_command(struct pmc *pmc, char *str)
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
		return parse_target(pmc, id_str);

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

	idtab[id].func(pmc, action, id, str);

	return 0;
}
