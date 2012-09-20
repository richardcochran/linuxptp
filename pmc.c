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

#include "ds.h"
#include "msg.h"
#include "print.h"
#include "tlv.h"
#include "transport.h"
#include "util.h"

#define BAD_ACTION   -1
#define BAD_ID       -1
#define AMBIGUOUS_ID -2
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define P41 ((double)(1ULL << 41))

static UInteger16 sequence_id;
static UInteger8 boundary_hops = 1;
static UInteger8 domain_number;
static UInteger8 transport_specific;
static struct PortIdentity port_identity;

static struct transport *transport;
static struct fdarray fdarray;

static void do_get_action(int action, int index);
static void not_supported(int action, int index);
static void null_management(int action, int index);

struct management_id {
	char name[64];
	int code;
	void (*func)(int action, int index);
};

struct management_id idtab[] = {
/* Clock management ID values */
	{ "USER_DESCRIPTION", USER_DESCRIPTION, not_supported },
	{ "SAVE_IN_NON_VOLATILE_STORAGE", SAVE_IN_NON_VOLATILE_STORAGE, not_supported },
	{ "RESET_NON_VOLATILE_STORAGE", RESET_NON_VOLATILE_STORAGE, not_supported },
	{ "INITIALIZE", INITIALIZE, not_supported },
	{ "FAULT_LOG", FAULT_LOG, not_supported },
	{ "FAULT_LOG_RESET", FAULT_LOG_RESET, not_supported },
	{ "DEFAULT_DATA_SET", DEFAULT_DATA_SET, not_supported },
	{ "CURRENT_DATA_SET", CURRENT_DATA_SET, do_get_action },
	{ "PARENT_DATA_SET", PARENT_DATA_SET, not_supported },
	{ "TIME_PROPERTIES_DATA_SET", TIME_PROPERTIES_DATA_SET, not_supported },
	{ "PRIORITY1", PRIORITY1, not_supported },
	{ "PRIORITY2", PRIORITY2, not_supported },
	{ "DOMAIN", DOMAIN, not_supported },
	{ "SLAVE_ONLY", SLAVE_ONLY, not_supported },
	{ "TIME", TIME, not_supported },
	{ "CLOCK_ACCURACY", CLOCK_ACCURACY, not_supported },
	{ "UTC_PROPERTIES", UTC_PROPERTIES, not_supported },
	{ "TRACEABILITY_PROPERTIES", TRACEABILITY_PROPERTIES, not_supported },
	{ "TIMESCALE_PROPERTIES", TIMESCALE_PROPERTIES, not_supported },
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
/* Port management ID values */
	{ "NULL_MANAGEMENT", NULL_MANAGEMENT, null_management },
	{ "CLOCK_DESCRIPTION", CLOCK_DESCRIPTION, not_supported },
	{ "PORT_DATA_SET", PORT_DATA_SET, not_supported },
	{ "LOG_ANNOUNCE_INTERVAL", LOG_ANNOUNCE_INTERVAL, not_supported },
	{ "ANNOUNCE_RECEIPT_TIMEOUT", ANNOUNCE_RECEIPT_TIMEOUT, not_supported },
	{ "LOG_SYNC_INTERVAL", LOG_SYNC_INTERVAL, not_supported },
	{ "VERSION_NUMBER", VERSION_NUMBER, not_supported },
	{ "ENABLE_PORT", ENABLE_PORT, not_supported },
	{ "DISABLE_PORT", DISABLE_PORT, not_supported },
	{ "UNICAST_NEGOTIATION_ENABLE", UNICAST_NEGOTIATION_ENABLE, not_supported },
	{ "UNICAST_MASTER_TABLE", UNICAST_MASTER_TABLE, not_supported },
	{ "UNICAST_MASTER_MAX_TABLE_SIZE", UNICAST_MASTER_MAX_TABLE_SIZE, not_supported },
	{ "ACCEPTABLE_MASTER_TABLE_ENABLED", ACCEPTABLE_MASTER_TABLE_ENABLED, not_supported },
	{ "ALTERNATE_MASTER", ALTERNATE_MASTER, not_supported },
	{ "TRANSPARENT_CLOCK_PORT_DATA_SET", TRANSPARENT_CLOCK_PORT_DATA_SET, not_supported },
	{ "DELAY_MECHANISM", DELAY_MECHANISM, not_supported },
	{ "LOG_MIN_PDELAY_REQ_INTERVAL", LOG_MIN_PDELAY_REQ_INTERVAL, not_supported },
};

static struct ptp_message *pmc_message(uint8_t action)
{
	struct ptp_message *msg;
	int pdulen;

	msg = msg_allocate();
	if (!msg)
		return NULL;

	pdulen = sizeof(struct management_msg);
	msg->hwts.type = TS_SOFTWARE;

	msg->header.tsmt               = MANAGEMENT | transport_specific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = domain_number;
	msg->header.sourcePortIdentity = port_identity;
	msg->header.sequenceId         = sequence_id++;
	msg->header.control            = CTL_MANAGEMENT;
	msg->header.logMessageInterval = 0x7f;

	memset(&msg->management.targetPortIdentity, 0xff,
	       sizeof(msg->management.targetPortIdentity));
	msg->management.startingBoundaryHops = boundary_hops;
	msg->management.boundaryHops = boundary_hops;
	msg->management.flags = action;

	return msg;
}

static int pmc_send(struct ptp_message *msg, int pdulen)
{
	int cnt, err;
	err = msg_pre_send(msg);
	if (err) {
		fprintf(stderr, "msg_pre_send failed\n");
		return -1;
	}
	cnt = transport_send(transport, &fdarray, 0, msg, pdulen, &msg->hwts);
	if (cnt < 0) {
		fprintf(stderr, "failed to send message\n");
		return -1;
	}
	return 0;
}

static char *action_string[] = {
	"GET",
	"SET",
	"RESPONSE",
	"COMMAND",
	"ACKNOWLEDGE",
};

#define IFMT "\n\t\t"

static void pmc_show(struct ptp_message *msg, FILE *fp)
{
	int action;
	struct TLV *tlv;
	struct management_tlv *mgt;
	struct currentDS *cds;
	struct time_status_np *tsn;
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
	switch (mgt->id) {
	case CURRENT_DATA_SET:
		cds = (struct currentDS *) mgt->data;
		fprintf(fp, "CURRENT_DATA_SET "
			IFMT "stepsRemoved     %hd "
			IFMT "offsetFromMaster %.1f "
			IFMT "meanPathDelay    %.1f ",
			cds->stepsRemoved, cds->offsetFromMaster / 65536.0,
			cds->meanPathDelay / 65536.0);
		break;
	case TIME_STATUS_NP:
		tsn = (struct time_status_np *) mgt->data;
		fprintf(fp, "TIME_STATUS_NP "
			IFMT "master_offset              %lld "
			IFMT "ingress_time               %lld "
			IFMT "cumulativeScaledRateOffset %+.9f "
			IFMT "scaledLastGmPhaseChange    %d "
			IFMT "gmTimeBaseIndicator        %hu "
			IFMT "lastGmPhaseChange          0x%04hx'%016llx.%04hx "
			IFMT "gmPresent                  %s "
			IFMT "gmIdentity                 %s ",
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
	}
out:
	fprintf(fp, "\n");
	fflush(fp);
}

static void get_action(int id)
{
	int pdulen;
	struct ptp_message *msg;
	struct management_tlv *mgt;
	msg = pmc_message(GET);
	if (!msg) {
		return;
	}
	mgt = (struct management_tlv *) msg->management.suffix;
	mgt->type = TLV_MANAGEMENT;
	mgt->length = 2;
	mgt->id = id;
	pdulen = msg->header.messageLength + sizeof(*mgt);
	msg->header.messageLength = pdulen;
	msg->tlv_count = 1;
	pmc_send(msg, pdulen);
	msg_put(msg);
}

static void do_get_action(int action, int index)
{
	if (action == GET)
		get_action(idtab[index].code);
	else
		fprintf(stderr, "%s only allows GET\n", idtab[index].name);
}

static void not_supported(int action, int index)
{
	fprintf(stdout, "sorry, %s not supported yet\n", idtab[index].name);
}

static void null_management(int action, int index)
{
	if (action == GET)
		get_action(idtab[index].code);
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

	idtab[id].func(action, id);

	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
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
		"           for network and '/tmp/pmc' for UDS.\n"
		" -t [hex]  transport specific field, default 0x0\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *iface_name = NULL, *progname;
	int c, cnt, length, tmo = -1;
	char line[1024];
	enum transport_type transport_type = TRANS_UDP_IPV4;
	struct ptp_message *msg;
#define N_FD 2
	struct pollfd pollfd[N_FD];

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "246u""b:d:hi:t:"))) {
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
		case 't':
			if (1 == sscanf(optarg, "%x", &c))
				transport_specific = c << 4;
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
		iface_name = transport_type == TRANS_UDS ? "/tmp/pmc" : "eth0";
	}
	if (transport_type != TRANS_UDS &&
	    generate_clock_identity(&port_identity.clockIdentity, iface_name)) {
		fprintf(stderr, "failed to generate a clock identity\n");
		return -1;
	}
	port_identity.portNumber = 1;
	transport = transport_create(transport_type);
	if (!transport) {
		fprintf(stderr, "failed to create transport\n");
		return -1;
	}
	if (transport_open(transport, iface_name, &fdarray, TS_SOFTWARE)) {
		fprintf(stderr, "failed to open transport\n");
		transport_destroy(transport);
		return -1;
	}

	pollfd[0].fd = STDIN_FILENO;
	pollfd[0].events = POLLIN|POLLPRI;
	pollfd[1].fd = fdarray.fd[FD_GENERAL];
	pollfd[1].events = POLLIN|POLLPRI;

	print_set_syslog(1);
	print_set_verbose(1);

	while (1) {
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
				tmo = 1000;
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
			if (do_command(line)) {
				fprintf(stderr, "bad command: %s\n", line);
			}
		}
		if (pollfd[1].revents & (POLLIN|POLLPRI)) {
			msg = msg_allocate();
			if (!msg) {
				fprintf(stderr, "low memory\n");
				return -1;
			}
			msg->hwts.type = TS_SOFTWARE;
			cnt = transport_recv(transport, pollfd[1].fd, msg,
					     sizeof(msg->data), &msg->hwts);
			if (cnt <= 0) {
				fprintf(stderr, "recv message failed\n");
			} else if (msg_post_recv(msg, cnt)) {
				fprintf(stderr, "bad message\n");
			} else {
				pmc_show(msg, stdout);
			}
			msg_put(msg);
		}
	}

	transport_close(transport, &fdarray);
	transport_destroy(transport);
	return 0;
}
