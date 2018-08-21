/**
 * @file snmp4lptp.c
 * @brief Implements SNMP sub agent program for linuxptp
 * @note Copyright (C) 2018 Anders Selhammer <anders.selhammer@est.tech>
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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "config.h"
#include "pmc_common.h"
#include "print.h"
#include "snmp4lptp_mib.h"
#include "util.h"

#define SNMP_NFD 1
static struct pmc *pmc;

struct ptp_message* snmp4lptp_run_pmc(char *cmd)
{
	struct pollfd pollfd[SNMP_NFD];
	int cnt, tmo = 100;

	pollfd[0].fd = pmc_get_transport_fd(pmc);
	pollfd[0].events = POLLIN | POLLPRI;

	if (cmd && pmc_do_command(pmc, cmd)) {
		pr_err("bad command: %s", cmd);
	}

	while (is_running()) {
		cnt = poll(pollfd, SNMP_NFD, tmo);
		if (cnt < 0) {
			if (EINTR == errno) {
				continue;
			} else {
				pr_emerg("poll failed");
				break;
			}
		} else if (!cnt) {
			break;
		}

		if (pollfd[0].revents & (POLLIN|POLLPRI)) {
			return pmc_recv(pmc);
		}
	}
	return NULL;
}

static int open_pmc(struct config *cfg)
{
	char uds_local[MAX_IFNAME_SIZE + 1];
	snprintf(uds_local, sizeof(uds_local), "/var/run/snmp4lptp.%d", getpid());

	pmc = pmc_create(cfg, TRANS_UDS, uds_local, 0,
			 config_get_int(cfg, NULL, "domainNumber"),
			 config_get_int(cfg, NULL, "transportSpecific") << 4,
			 1);

	return pmc ? 0 : -1;
}

static int open_snmp()
{
	snmp_enable_calllog();
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
			       NETSNMP_DS_AGENT_ROLE, 1);
	init_agent("linuxptpAgent");

	init_snmp("linuxptpAgent");

	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" -f [file] read configuration from 'file'\n"
		" -h        prints this message and exits\n"
		" -m        print messages to stdout\n"
		" -q        do not print messages to the syslog\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *config = NULL, *progname;
	int c, err = 0, index;
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
	while (EOF != (c = getopt_long(argc, argv, "f:hmq", opts, &index))) {
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
		case 'h':
			usage(progname);
			err = -1;
			goto out;
		case 'm':
			config_set_int(cfg, "verbose", 1);
			break;
		case 'q':
			config_set_int(cfg, "use_syslog", 0);
			break;
		case '?':
		default:
			usage(progname);
			err = -1;
			goto out;
		}
	}

	if (config && (err = config_read(config, cfg))) {
		err = -1;
		goto out;
	}

	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));


	if (open_pmc(cfg)) {
		err = -1;
		goto pmc_out;
	}

	if (open_snmp()) {
		err = -1;
		goto snmp_out;
	}

	while (is_running()) {
		agent_check_and_process(1);
	}

	snmp_shutdown("linuxptpAgent");

snmp_out:
	pmc_destroy(pmc);
	msg_cleanup();
pmc_out:
out:
	config_destroy(cfg);
	return err;
}
