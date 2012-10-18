/**
 * @file config.c
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
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
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "ether.h"
#include "print.h"

enum config_section {
	GLOBAL_SECTION,
	PORT_SECTION,
	UNKNOWN_SECTION,
};

static int scan_mode(char *s, enum config_section *section)
{
	if (0 == strcasecmp(s, "[global]\n")) {
		*section = GLOBAL_SECTION;
		return 1;
	} else if (s[0] == '[') {
		char c;
		*section = PORT_SECTION;
		/* Replace square brackets with white space. */
		while (0 != (c = *s)) {
			if (c == '[' || c == ']')
				*s = ' ';
			s++;
		}
		return 1;
	} else {
		return 0;
	}
}

static int scan_pod(const char *s, struct port_defaults *pod)
{
	int val;
	Integer8 i8;
	UInteger8 u8;

	if (1 == sscanf(s, " logAnnounceInterval %hhd", &i8)) {

		pod->logAnnounceInterval = i8;
		return 1;

	} else if (1 == sscanf(s, " logSyncInterval %hhd", &i8)) {

		pod->logSyncInterval = i8;
		return 1;

	} else if (1 == sscanf(s, " logMinDelayReqInterval %hhd", &i8)) {

		pod->logMinDelayReqInterval = i8;
		return 1;

	} else if (1 == sscanf(s, " logMinPdelayReqInterval %hhd", &i8)) {

		pod->logMinPdelayReqInterval = i8;
		return 1;

	} else if (1 == sscanf(s, " announceReceiptTimeout %hhu", &u8)) {

		pod->announceReceiptTimeout = u8;
		return 1;

	} else if (1 == sscanf(s, " transportSpecific %hhx", &u8)) {

		pod->transportSpecific = u8 << 4;
		return 1;

	} else if (1 == sscanf(s, " path_trace_enabled %u", &val)) {

		pod->path_trace_enabled = val ? 1 : 0;
		return 1;

	} else if (1 == sscanf(s, " follow_up_info %u", &val)) {

		pod->follow_up_info = val ? 1 : 0;
		return 1;
	}

	return 0;
}

static void scan_port_line(const char *s, struct config *cfg, int p)
{
	char string[1024];

	if (scan_pod(s, &cfg->iface[p].pod)) {

		/* nothing to do here */

	} else if (1 == sscanf(s, " network_transport %1023s", string)) {

		if (0 == strcasecmp("L2", string))

			cfg->iface[p].transport = TRANS_IEEE_802_3;

		else if (0 == strcasecmp("UDPv4", string))

			cfg->iface[p].transport = TRANS_UDP_IPV4;

		else if (0 == strcasecmp("UDPv6", string))

			cfg->iface[p].transport = TRANS_UDP_IPV6;

	} else if (1 == sscanf(s, " delay_mechanism %1023s", string)) {

		if (0 == strcasecmp("Auto", string))

			cfg->iface[p].dm = DM_AUTO;

		else if (0 == strcasecmp("E2E", string))

			cfg->iface[p].dm = DM_E2E;

		else if (0 == strcasecmp("P2P", string))

			cfg->iface[p].dm = DM_P2P;

	}
}

static void scan_global_line(const char *s, struct config *cfg)
{
	double df;
	int i, val, cfg_ignore = cfg->cfg_ignore;
	UInteger16 u16;
	UInteger8 u8;
	unsigned char mac[MAC_LEN];
	char string[1024];

	struct defaultDS *dds = &cfg->dds;
	struct port_defaults *pod = &cfg->pod;

	if (scan_pod(s, pod)) {

		/* nothing to do here */

	} else if (1 == sscanf(s, " twoStepFlag %d", &val)) {

		if (val) /* TODO - implement one step */
			dds->twoStepFlag = val ? 1 : 0;

	} else if (1 == sscanf(s, " slaveOnly %d", &val)) {

		if (!(cfg_ignore & CFG_IGNORE_SLAVEONLY))
			dds->slaveOnly = val ? 1 : 0;

	} else if (1 == sscanf(s, " priority1 %hhu", &u8)) {

		dds->priority1 = u8;

	} else if (1 == sscanf(s, " priority2 %hhu", &u8)) {

		dds->priority2 = u8;

	} else if (1 == sscanf(s, " domainNumber %hhu", &u8)) {

		if (u8 < 128)
			dds->domainNumber = u8;

	} else if (1 == sscanf(s, " clockClass %hhu", &u8)) {

		if (!(cfg_ignore & CFG_IGNORE_SLAVEONLY))
			dds->clockQuality.clockClass = u8;

	} else if (1 == sscanf(s, " clockAccuracy %hhx", &u8)) {

		dds->clockQuality.clockAccuracy = u8;

	} else if (1 == sscanf(s, " offsetScaledLogVariance %hx", &u16)) {

		dds->clockQuality.offsetScaledLogVariance = u16;

	} else if (1 == sscanf(s, " free_running %d", &val)) {

		dds->free_running = val ? 1 : 0;

	} else if (1 == sscanf(s, " freq_est_interval %d", &val)) {

		if (val >= 0) {
			dds->freq_est_interval = val;
			pod->freq_est_interval = val;
		}

	} else if (1 == sscanf(s, " assume_two_step %u", &val)) {

		*cfg->assume_two_step = val ? 1 : 0;

	} else if (1 == sscanf(s, " tx_timestamp_retries %u", &val)) {

		if (val > 0)
			*cfg->tx_timestamp_retries = val;

	} else if (1 == sscanf(s, " rx_timestamp_l2only %u", &val)) {

		*cfg->rx_timestamp_l2only = val ? 1 : 0;

	} else if (1 == sscanf(s, " pi_proportional_const %lf", &df)) {

		if (df > 0.0 && df < 1.0)
			*cfg->pi_proportional_const = df;

	} else if (1 == sscanf(s, " pi_integral_const %lf", &df)) {

		if (df > 0.0 && df < 1.0)
			*cfg->pi_integral_const = df;

	} else if (1 == sscanf(s, " pi_offset_const %lf", &df)) {

		if (df >= 0.0)
			*cfg->pi_offset_const = df;

	} else if (MAC_LEN == sscanf(s, " ptp_dst_mac %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])) {

		for (i = 0; i < MAC_LEN; i++)
			cfg->ptp_dst_mac[i] = mac[i];

	} else if (MAC_LEN == sscanf(s, " p2p_dst_mac %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])) {

		for (i = 0; i < MAC_LEN; i++)
			cfg->p2p_dst_mac[i] = mac[i];

	} else if (1 == sscanf(s, " logging_level %d", &val)) {

		if (!(cfg_ignore & CFG_IGNORE_PRINT_LEVEL)) {
			if (val >= PRINT_LEVEL_MIN && val <= PRINT_LEVEL_MAX)
				cfg->print_level = val;
		}

	} else if (1 == sscanf(s, " verbose %d", &val)) {

		if (!(cfg_ignore & CFG_IGNORE_VERBOSE))
			cfg->verbose = val ? 1 : 0;

	} else if (1 == sscanf(s, " use_syslog %d", &val)) {

		if (!(cfg_ignore & CFG_IGNORE_USE_SYSLOG))
			cfg->use_syslog = val ? 1 : 0;

	} else if (1 == sscanf(s, " time_stamping %1023s", string)) {

		if (!(cfg_ignore & CFG_IGNORE_TIMESTAMPING)) {

			if (0 == strcasecmp("hardware", string))

				cfg->timestamping = TS_HARDWARE;

			else if (0 == strcasecmp("software", string))

				cfg->timestamping = TS_SOFTWARE;

			else if (0 == strcasecmp("legacy", string))

				cfg->timestamping = TS_LEGACY_HW;
		}

	} else if (1 == sscanf(s, " delay_mechanism %1023s", string)) {

		if (!(cfg_ignore & CFG_IGNORE_DM)) {

			if (0 == strcasecmp("E2E", string))

				cfg->dm = DM_E2E;

			else if (0 == strcasecmp("P2P", string))

				cfg->dm = DM_P2P;

			else if (0 == strcasecmp("Auto", string))

				cfg->dm = DM_AUTO;
		}

	} else if (1 == sscanf(s, " network_transport %1023s", string)) {

		if (!(cfg_ignore & CFG_IGNORE_TRANSPORT)) {

			if (0 == strcasecmp("UDPv4", string))

				cfg->transport = TRANS_UDP_IPV4;

			else if (0 == strcasecmp("UDPv6", string))

				cfg->transport = TRANS_UDP_IPV6;

			else if (0 == strcasecmp("L2", string))

				cfg->transport = TRANS_IEEE_802_3;

		}

	} else if (1 == sscanf(s, " clock_servo %1023s", string)) {

		if (0 == strcasecmp("pi", string))

			cfg->clock_servo = CLOCK_SERVO_PI;

	}
}

int config_read(char *name, struct config *cfg)
{
	enum config_section current_section = GLOBAL_SECTION;
	FILE *fp;
	char line[1024];
	int current_port;

	fp = 0 == strncmp(name, "-", 2) ? stdin : fopen(name, "r");

	if (!fp) {
		perror("fopen");
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (scan_mode(line, &current_section) ) {
			if (current_section == PORT_SECTION) {
				char port[17];
				if (1 != sscanf(line, " %16s", port)) {
					current_section = UNKNOWN_SECTION;
					continue;
				}
				current_port = config_create_interface(port, cfg);
				if (current_port < 0) {
					return -1;
				}
			}
			continue;
		}

		switch(current_section) {
		case GLOBAL_SECTION:
			scan_global_line(line, cfg);
			break;
		case PORT_SECTION:
			scan_port_line(line, cfg, current_port);
			break;
		default:
			continue;
		}
	}

	fclose(fp);
	return 0;
}

/* returns the number matching that interface, or -1 on failure */
int config_create_interface(char *name, struct config *cfg)
{
	struct interface *iface;
	int i;

	if (cfg->nports >= MAX_PORTS) {
		return -1;
	}

	iface = &cfg->iface[cfg->nports];

	/* only create each interface once (by name) */
	for(i = 0; i < cfg->nports; i++) {
		if (0 == strncmp(name, cfg->iface[i].name, MAX_IFNAME_SIZE))
			return i;
	}

	strncpy(iface->name, name, MAX_IFNAME_SIZE);
	iface->dm = cfg->dm;
	iface->transport = cfg->transport;
	memcpy(&iface->pod, &cfg->pod, sizeof(cfg->pod));

	cfg->nports++;

	return i;
}
