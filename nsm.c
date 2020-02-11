/**
 * @file nsm.c
 * @brief NSM client program
 * @note Copyright (C) 2018 Richard Cochran <richardcochran@gmail.com>
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

#include "config.h"
#include "print.h"
#include "rtnl.h"
#include "util.h"
#include "version.h"

#define IFMT		"\n\t\t"
#define NSM_NFD		3

struct interface {
	STAILQ_ENTRY(interface) list;
};

struct nsm {
	struct config		*cfg;
	struct fdarray		fda;
	struct transport	*trp;
	struct tsproc		*tsproc;
	struct ptp_message	*nsm_delay_req;
	struct ptp_message	*nsm_delay_resp;
	struct ptp_message	*nsm_sync;
	struct ptp_message	*nsm_fup;
	struct PortIdentity	port_identity;
	UInteger16		sequence_id;
	const char		*name;
} the_nsm;

static void nsm_help(FILE *fp);
static int nsm_request(struct nsm *nsm, char *target);
static void nsm_reset(struct nsm *nsm);

static int nsm_command(struct nsm *nsm, const char *cmd)
{
	char action_str[10+1] = {0}, id_str[64+1] = {0};

	if (0 == strncasecmp(cmd, "HELP", strlen(cmd))) {
		nsm_help(stdout);
		return 0;
	}
	if (2 != sscanf(cmd, " %10s %64s", action_str, id_str)) {
		pr_err("bad command: %s", cmd);
		return -1;
	}
	if (0 == strncasecmp(action_str, "NSM", strlen(action_str))) {
		return nsm_request(nsm, id_str);
	}
	pr_err("bad command: %s", cmd);
	return -1;
}

static int nsm_complete(struct nsm *nsm)
{
	if (!nsm->nsm_sync) {
		return 0;
	}
	if (one_step(nsm->nsm_sync)) {
		return nsm->nsm_delay_resp ? 1 : 0;
	}
	return (nsm->nsm_delay_resp && nsm->nsm_fup) ? 1 : 0;
}

static int64_t nsm_compute_offset(struct tsproc *tsp,
				  struct ptp_message *syn,
				  struct ptp_message *fup,
				  struct ptp_message *req,
				  struct ptp_message *resp)
{
	tmv_t c1, c2, c3, t1, t1c, t2, t3, t4, t4c, offset;

	c1 = correction_to_tmv(syn->header.correction);
	c2 = correction_to_tmv(fup->header.correction);
	c3 = correction_to_tmv(resp->header.correction);

	t1 = timestamp_to_tmv(fup->ts.pdu);
	t2 = syn->hwts.ts;
	t3 = req->hwts.ts;
	t4 = timestamp_to_tmv(resp->ts.pdu);

	t1c = tmv_add(t1, tmv_add(c1, c2));
	t4c = tmv_sub(t4, c3);

	tsproc_reset(tsp, 1);
	tsproc_down_ts(tsp, t1c, t2);
	tsproc_up_ts(tsp, t3, t4c);
	tsproc_update_offset(tsp, &offset, NULL);

	return tmv_to_nanoseconds(offset);
}

static void nsm_close(struct nsm *nsm)
{
	nsm_reset(nsm);
	transport_close(nsm->trp, &nsm->fda);
	transport_destroy(nsm->trp);
	tsproc_destroy(nsm->tsproc);
}

static void nsm_handle_msg(struct nsm *nsm, struct ptp_message *msg, FILE *fp)
{
	struct nsm_resp_tlv_head *head;
	struct nsm_resp_tlv_foot *foot;
	struct timePropertiesDS *tp;
	struct PortAddress *paddr;
	struct currentDS cds;
	struct parentDS *pds;
	struct Timestamp ts;
	unsigned char *ptr;
	int64_t offset;

	if (!nsm->nsm_delay_req) {
		return;
	}
	if (msg->header.sequenceId !=
	    ntohs(nsm->nsm_delay_req->header.sequenceId)) {
		return;
	}
	if (!msg_unicast(msg)) {
		return;
	}

	switch (msg_type(msg)) {
	case SYNC:
		if (!nsm->nsm_sync) {
			nsm->nsm_sync = msg;
			msg_get(msg);
		}
		break;
	case FOLLOW_UP:
		if (!nsm->nsm_fup) {
			nsm->nsm_fup = msg;
			msg_get(msg);
		}
		break;
	case DELAY_RESP:
		if (!nsm->nsm_delay_resp) {
			nsm->nsm_delay_resp = msg;
			msg_get(msg);
		}
		break;
	case DELAY_REQ:
	case PDELAY_REQ:
	case PDELAY_RESP:
	case PDELAY_RESP_FOLLOW_UP:
	case ANNOUNCE:
	case SIGNALING:
	case MANAGEMENT:
		return;
	}

	if (!nsm_complete(nsm)) {
		return;
	}

	head = (struct nsm_resp_tlv_head *) nsm->nsm_delay_resp->delay_resp.suffix;
	paddr = &head->parent_addr;

	ptr = (unsigned char *) head;
	ptr += sizeof(*head) + paddr->addressLength;
	foot = (struct nsm_resp_tlv_foot *) ptr;

	pds = &foot->parent;
	memcpy(&cds, &foot->current, sizeof(cds));
	tp = &foot->timeprop;
	memcpy(&ts, &foot->lastsync, sizeof(ts));

	offset = nsm_compute_offset(nsm->tsproc, nsm->nsm_sync, nsm->nsm_fup,
				    nsm->nsm_delay_req, nsm->nsm_delay_resp);

	fprintf(fp, "NSM MEASUREMENT COMPLETE"
		IFMT "offset                                %" PRId64
		IFMT "portState                             %s"
		IFMT "parentPortAddress                     %hu %s\n",
		offset,
		ps_str[head->port_state],
		head->parent_addr.networkProtocol,
		portaddr2str(&head->parent_addr));
	fprintf(fp, "\tparentDataset"
		IFMT "parentPortIdentity                    %s"
		IFMT "parentStats                           %hhu"
		IFMT "observedParentOffsetScaledLogVariance 0x%04hx"
		IFMT "observedParentClockPhaseChangeRate    0x%08x"
		IFMT "grandmasterPriority1                  %hhu"
		IFMT "gm.ClockClass                         %hhu"
		IFMT "gm.ClockAccuracy                      0x%02hhx"
		IFMT "gm.OffsetScaledLogVariance            0x%04hx"
		IFMT "grandmasterPriority2                  %hhu"
		IFMT "grandmasterIdentity                   %s\n",
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
	fprintf(fp, "\tcurrentDataset"
		IFMT "stepsRemoved                          %hd"
		IFMT "offsetFromMaster                      %.1f"
		IFMT "meanPathDelay                         %.1f\n",
		cds.stepsRemoved, cds.offsetFromMaster / 65536.0,
		cds.meanPathDelay / 65536.0);
	fprintf(fp, "\ttimePropertiesDataset"
		IFMT "currentUtcOffset                      %hd"
		IFMT "leap61                                %d"
		IFMT "leap59                                %d"
		IFMT "currentUtcOffsetValid                 %d"
		IFMT "ptpTimescale                          %d"
		IFMT "timeTraceable                         %d"
		IFMT "frequencyTraceable                    %d"
		IFMT "timeSource                            0x%02hhx\n",
		tp->currentUtcOffset,
		tp->flags & LEAP_61 ? 1 : 0,
		tp->flags & LEAP_59 ? 1 : 0,
		tp->flags & UTC_OFF_VALID ? 1 : 0,
		tp->flags & PTP_TIMESCALE ? 1 : 0,
		tp->flags & TIME_TRACEABLE ? 1 : 0,
		tp->flags & FREQ_TRACEABLE ? 1 : 0,
		tp->timeSource);
	fprintf(fp, "\tlastSyncTimestamp    %" PRId64 ".%09u\n",
		((uint64_t)ts.seconds_lsb) | (((uint64_t)ts.seconds_msb) << 32),
		ts.nanoseconds);

	fflush(fp);
	nsm_reset(nsm);
}

static void nsm_help(FILE *fp)
{
	fprintf(fp, "\tSend a NetSync Monitor request to a specific port address:\n");
	fprintf(fp, "\n");
	fprintf(fp, "\tNSM 111.222.333.444\n");
	fprintf(fp, "\tNSM aa:bb:cc:dd:ee:ff\n");
	fprintf(fp, "\n");
}

static int nsm_open(struct nsm *nsm, struct config *cfg)
{
	enum transport_type transport;
	char ts_label[IF_NAMESIZE];
	const char *ifname, *name;
	struct interface *iface;
	int count = 0;

	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		ifname = interface_name(iface);
		memset(ts_label, 0, sizeof(ts_label));
		rtnl_get_ts_device(ifname, ts_label);
		interface_set_label(iface, ts_label);
		interface_ensure_tslabel(iface);
		count++;
	}
	if (count != 1) {
		pr_err("need exactly one interface");
		return -1;
	}
	iface = STAILQ_FIRST(&cfg->interfaces);
	nsm->name = name = interface_name(iface);
	nsm->cfg = cfg;

	transport = config_get_int(cfg, name, "network_transport");

	if (generate_clock_identity(&nsm->port_identity.clockIdentity, name)) {
		pr_err("failed to generate a clock identity");
		return -1;
	}
	nsm->port_identity.portNumber = 1;

	nsm->tsproc = tsproc_create(TSPROC_RAW, FILTER_MOVING_AVERAGE, 10);
	if (!nsm->tsproc) {
		pr_err("failed to create time stamp processor");
		goto no_tsproc;
	}
	nsm->trp = transport_create(cfg, transport);
	if (!nsm->trp) {
		pr_err("failed to create transport");
		goto no_trans;
	}
	if (transport_open(nsm->trp, iface, &nsm->fda,
			   config_get_int(cfg, NULL, "time_stamping"))) {
		pr_err("failed to open transport");
		goto open_failed;
	}
	return 0;

open_failed:
	transport_destroy(nsm->trp);
no_trans:
	tsproc_destroy(nsm->tsproc);
no_tsproc:
	return -1;
}

static struct ptp_message *nsm_recv(struct nsm *nsm, int fd)
{
	struct ptp_message *msg;
	int cnt, err;

	msg = msg_allocate();
	if (!msg) {
		pr_err("low memory");
		return NULL;
	}
	msg->hwts.type = config_get_int(nsm->cfg, NULL, "time_stamping");

	cnt = transport_recv(nsm->trp, fd, msg);
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

static int nsm_request(struct nsm *nsm, char *target)
{
	enum transport_type type = transport_type(nsm->trp);
	UInteger8 transportSpecific;
	struct ptp_message *msg;
	struct tlv_extra *extra;
	Integer64 asymmetry;
	struct address dst;
	int cnt, err;

	if (str2addr(type, target, &dst)) {
		return -1;
	}

	msg = msg_allocate();
	if (!msg) {
		return -1;
	}

	transportSpecific = config_get_int(nsm->cfg, nsm->name, "transportSpecific");
	transportSpecific <<= 4;

	asymmetry = config_get_int(nsm->cfg, nsm->name, "delayAsymmetry");
	asymmetry <<= 16;

	msg->hwts.type = config_get_int(nsm->cfg, NULL, "time_stamping");

	msg->header.tsmt               = DELAY_REQ | transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = sizeof(struct delay_req_msg);
	msg->header.domainNumber       = config_get_int(nsm->cfg, NULL, "domainNumber");
	msg->header.correction         = -asymmetry;
	msg->header.sourcePortIdentity = nsm->port_identity;
	msg->header.sequenceId         = nsm->sequence_id++;
	msg->header.control            = CTL_DELAY_REQ;
	msg->header.logMessageInterval = 0x7f;

	msg->address = dst;
	msg->header.flagField[0] |= UNICAST;

	extra = msg_tlv_append(msg, sizeof(struct TLV));
	if (!extra) {
		msg_put(msg);
		return -ENOMEM;
	}
	extra->tlv->type = TLV_PTPMON_REQ;
	extra->tlv->length = 0;

	err = msg_pre_send(msg);
	if (err) {
		pr_err("msg_pre_send failed");
		goto out;
	}
	cnt = transport_sendto(nsm->trp, &nsm->fda, TRANS_EVENT, msg);
	if (cnt <= 0) {
		pr_err("transport_sendto failed");
		err = -1;
		goto out;
	}
	if (msg_sots_missing(msg)) {
		pr_err("missing timestamp on transmitted delay request");
		err = -1;
		goto out;
	}
	nsm_reset(nsm);
	nsm->nsm_delay_req = msg;
	return 0;
out:
	msg_put(msg);
	return err;
}

static void nsm_reset(struct nsm *nsm)
{
	if (nsm->nsm_delay_req) {
		msg_put(nsm->nsm_delay_req);
	}
	if (nsm->nsm_delay_resp) {
		msg_put(nsm->nsm_delay_resp);
	}
	if (nsm->nsm_sync) {
		msg_put(nsm->nsm_sync);
	}
	if (nsm->nsm_fup) {
		msg_put(nsm->nsm_fup);
	}
	nsm->nsm_delay_req = NULL;
	nsm->nsm_delay_resp = NULL;
	nsm->nsm_sync = NULL;
	nsm->nsm_fup = NULL;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" -f [file] read configuration from 'file'\n"
		" -h        prints this message and exits\n"
		" -i [dev]  interface device to use\n"
		" -v        prints the software version and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	int batch_mode = 0, c, cnt, err = 0, index, length, tmo = -1;
	char *cmd = NULL, *config = NULL, line[1024], *progname;
	struct pollfd pollfd[NSM_NFD];
	struct nsm *nsm = &the_nsm;
	struct ptp_message *msg;
	struct option *opts;
	struct config *cfg;

	if (handle_term_signals()) {
		return -1;
	}
	cfg = config_create();
	if (!cfg) {
		return -1;
	}
	opts = config_long_options(cfg);
	print_set_verbose(1);
	print_set_syslog(0);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv, "f:hi:v", opts, &index))) {
		switch (c) {
		case 0:
			if (config_parse_option(cfg, opts[index].name, optarg)) {
				config_destroy(cfg);
				return -1;
			}
			break;
		case 'f':
			config = optarg;
			break;
		case 'i':
			if (!config_create_interface(optarg, cfg)) {
				config_destroy(cfg);
				return -1;
			}
			break;
		case 'v':
			version_show(stdout);
			config_destroy(cfg);
			return 0;
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

	print_set_syslog(0);
	print_set_verbose(1);

	if (config && (err = config_read(config, cfg))) {
		goto out;
	}

	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	err = nsm_open(nsm, cfg);
	if (err) {
		goto out;
	}

	if (optind < argc) {
		batch_mode = 1;
	}

	pollfd[0].fd = nsm->fda.fd[0];
	pollfd[1].fd = nsm->fda.fd[1];
	pollfd[2].fd = batch_mode ? -1 : STDIN_FILENO;
	pollfd[0].events = POLLIN | POLLPRI;
	pollfd[1].events = POLLIN | POLLPRI;
	pollfd[2].events = batch_mode ? 0 : POLLIN | POLLPRI;

	while (is_running()) {
		if (batch_mode) {
			if (optind < argc && !nsm->nsm_delay_req) {
				cmd = argv[optind++];
				if (nsm_command(nsm, cmd)) {
					pr_err("command failed");
					continue;
				}
			}
			/* Wait a bit for any outstanding replies. */
			tmo = 100;
		}

		cnt = poll(pollfd, NSM_NFD, tmo);
		if (cnt < 0) {
			if (EINTR == errno) {
				continue;
			} else {
				pr_emerg("poll failed");
				err = -1;
				break;
			}
		} else if (!cnt && optind < argc) {
			/* For batch mode. No response received from target node,
			 * continue with next command. */
			nsm_reset(nsm);
			continue;
		} else if (!cnt) {
			break;
		}
		if (pollfd[2].revents & POLLHUP) {
			if (tmo == -1) {
				/* Wait a bit longer for outstanding replies. */
				tmo = 100;
				pollfd[2].fd = -1;
				pollfd[2].events = 0;
			} else {
				break;
			}
		}
		if (pollfd[2].revents & (POLLIN|POLLPRI)) {
			if (!fgets(line, sizeof(line), stdin)) {
				break;
			}
			length = strlen(line);
			if (length < 2) {
				continue;
			}
			line[length - 1] = 0;
			cmd = line;
			if (nsm_command(nsm, cmd)) {
				pr_err("command failed");
			}
		}
		if (pollfd[0].revents & (POLLIN|POLLPRI)) {
			msg = nsm_recv(nsm, pollfd[0].fd);
			if (msg) {
				nsm_handle_msg(nsm, msg, stdout);
				msg_put(msg);
			}
		}
		if (pollfd[1].revents & (POLLIN|POLLPRI)) {
			msg = nsm_recv(nsm, pollfd[1].fd);
			if (msg) {
				nsm_handle_msg(nsm, msg, stdout);
				msg_put(msg);
			}
		}
	}

	nsm_close(nsm);
out:
	msg_cleanup();
	config_destroy(cfg);
	return err;
}
