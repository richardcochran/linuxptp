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

static struct pmc *pmc;

#define IFMT "\n\t\t"

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
	struct tlv_extra *extra;
	struct portDS *p;
	struct port_ds_np *pnp;

	if (msg_type(msg) != MANAGEMENT) {
		return;
	}
	action = management_action(msg);
	if (action < GET || action > ACKNOWLEDGE) {
		return;
	}
	fprintf(fp, "\t%s seq %hu %s ",
		pid2str(&msg->header.sourcePortIdentity),
		msg->header.sequenceId, pmc_action_string(action));
	if (msg_tlv_count(msg) != 1) {
		goto out;
	}
	extra = TAILQ_FIRST(&msg->tlv_list);
	tlv = (struct TLV *) msg->management.suffix;
	if (tlv->type == TLV_MANAGEMENT) {
		fprintf(fp, "MANAGEMENT ");
	} else if (tlv->type == TLV_MANAGEMENT_ERROR_STATUS) {
		fprintf(fp, "MANAGEMENT_ERROR_STATUS ");
		goto out;
	} else {
		fprintf(fp, "unknown-tlv ");
		goto out;
	}
	mgt = (struct management_tlv *) msg->management.suffix;
	if (mgt->length == 2 && mgt->id != TLV_NULL_MANAGEMENT) {
		fprintf(fp, "empty-tlv ");
		goto out;
	}
	switch (mgt->id) {
	case TLV_CLOCK_DESCRIPTION:
		cd = &extra->cd;
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
	case TLV_USER_DESCRIPTION:
		fprintf(fp, "USER_DESCRIPTION "
			IFMT "userDescription  %s",
			text2str(extra->cd.userDescription));
		break;
	case TLV_DEFAULT_DATA_SET:
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
	case TLV_CURRENT_DATA_SET:
		cds = (struct currentDS *) mgt->data;
		fprintf(fp, "CURRENT_DATA_SET "
			IFMT "stepsRemoved     %hd"
			IFMT "offsetFromMaster %.1f"
			IFMT "meanPathDelay    %.1f",
			cds->stepsRemoved, cds->offsetFromMaster / 65536.0,
			cds->meanPathDelay / 65536.0);
		break;
	case TLV_PARENT_DATA_SET:
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
	case TLV_TIME_PROPERTIES_DATA_SET:
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
	case TLV_PRIORITY1:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "PRIORITY1 "
			IFMT "priority1 %hhu", mtd->val);
		break;
	case TLV_PRIORITY2:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "PRIORITY2 "
			IFMT "priority2 %hhu", mtd->val);
		break;
	case TLV_DOMAIN:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "DOMAIN "
			IFMT "domainNumber %hhu", mtd->val);
		break;
	case TLV_SLAVE_ONLY:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "SLAVE_ONLY "
			IFMT "slaveOnly %d", mtd->val & DDS_SLAVE_ONLY ? 1 : 0);
		break;
	case TLV_CLOCK_ACCURACY:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "CLOCK_ACCURACY "
			IFMT "clockAccuracy 0x%02hhx", mtd->val);
		break;
	case TLV_TRACEABILITY_PROPERTIES:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "TRACEABILITY_PROPERTIES "
			IFMT "timeTraceable      %d"
			IFMT "frequencyTraceable %d",
			mtd->val & TIME_TRACEABLE ? 1 : 0,
			mtd->val & FREQ_TRACEABLE ? 1 : 0);
		break;
	case TLV_TIMESCALE_PROPERTIES:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "TIMESCALE_PROPERTIES "
			IFMT "ptpTimescale %d", mtd->val & PTP_TIMESCALE ? 1 : 0);
		break;
	case TLV_TIME_STATUS_NP:
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
			(tsn->cumulativeScaledRateOffset + 0.0) / P41,
			tsn->scaledLastGmPhaseChange,
			tsn->gmTimeBaseIndicator,
			tsn->lastGmPhaseChange.nanoseconds_msb,
			tsn->lastGmPhaseChange.nanoseconds_lsb,
			tsn->lastGmPhaseChange.fractional_nanoseconds,
			tsn->gmPresent ? "true" : "false",
			cid2str(&tsn->gmIdentity));
		break;
	case TLV_GRANDMASTER_SETTINGS_NP:
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
	case TLV_PORT_DATA_SET:
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
	case TLV_PORT_DATA_SET_NP:
		pnp = (struct port_ds_np *) mgt->data;
		fprintf(fp, "PORT_DATA_SET_NP "
			IFMT "neighborPropDelayThresh %u"
			IFMT "asCapable               %d",
			pnp->neighborPropDelayThresh,
			pnp->asCapable ? 1 : 0);
		break;
	case TLV_LOG_ANNOUNCE_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "LOG_ANNOUNCE_INTERVAL "
			IFMT "logAnnounceInterval %hhd", mtd->val);
		break;
	case TLV_ANNOUNCE_RECEIPT_TIMEOUT:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "ANNOUNCE_RECEIPT_TIMEOUT "
			IFMT "announceReceiptTimeout %hhu", mtd->val);
		break;
	case TLV_LOG_SYNC_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "LOG_SYNC_INTERVAL "
			IFMT "logSyncInterval %hhd", mtd->val);
		break;
	case TLV_VERSION_NUMBER:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "VERSION_NUMBER "
			IFMT "versionNumber %hhu", mtd->val);
		break;
	case TLV_DELAY_MECHANISM:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "DELAY_MECHANISM "
			IFMT "delayMechanism %hhu", mtd->val);
		break;
	case TLV_LOG_MIN_PDELAY_REQ_INTERVAL:
		mtd = (struct management_tlv_datum *) mgt->data;
		fprintf(fp, "LOG_MIN_PDELAY_REQ_INTERVAL "
			IFMT "logMinPdelayReqInterval %hhd", mtd->val);
		break;
	}
out:
	fprintf(fp, "\n");
	fflush(fp);
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

int main(int argc, char *argv[])
{
	const char *iface_name = NULL;
	char *config = NULL, *progname;
	int c, cnt, index, length, tmo = -1, batch_mode = 0, zero_datalen = 0;
	int ret = 0;
	char line[1024], *command = NULL, uds_local[MAX_IFNAME_SIZE + 1];
	enum transport_type transport_type = TRANS_UDP_IPV4;
	UInteger8 boundary_hops = 1, domain_number = 0, transport_specific = 0;
	struct ptp_message *msg;
	struct option *opts;
	struct config *cfg;
#define N_FD 2
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
	while (EOF != (c = getopt_long(argc, argv, "246u""b:d:f:hi:s:t:vz",
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

	pmc = pmc_create(cfg, transport_type, iface_name, boundary_hops,
			 domain_number, transport_specific, zero_datalen);
	if (!pmc) {
		fprintf(stderr, "failed to create pmc\n");
		config_destroy(cfg);
		return -1;
	}

	pollfd[0].fd = batch_mode ? -1 : STDIN_FILENO;
	pollfd[1].fd = pmc_get_transport_fd(pmc);

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
			if (pmc_do_command(pmc, command)) {
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

out:
	config_destroy(cfg);
	return ret;
}
