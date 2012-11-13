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
#include <ctype.h>
#include "config.h"
#include "ether.h"
#include "print.h"

enum config_section {
	GLOBAL_SECTION,
	PORT_SECTION,
	UNKNOWN_SECTION,
};

enum parser_result {
	PARSED_OK,
	NOT_PARSED,
	BAD_VALUE,
};

static enum parser_result parse_section_line(char *s, enum config_section *section)
{
	if (!strcasecmp(s, "[global]")) {
		*section = GLOBAL_SECTION;
	} else if (s[0] == '[') {
		char c;
		*section = PORT_SECTION;
		/* Replace square brackets with white space. */
		while (0 != (c = *s)) {
			if (c == '[' || c == ']')
				*s = ' ';
			s++;
		}
	} else
		return NOT_PARSED;
	return PARSED_OK;
}

static enum parser_result parse_pod_setting(const char *option,
					    const char *value,
					    struct port_defaults *pod)
{
	int val;
	Integer8 i8;
	UInteger8 u8;

	if (!strcmp(option, "logAnnounceInterval")) {
		if (1 != sscanf(value, "%hhd", &i8))
			return BAD_VALUE;
		pod->logAnnounceInterval = i8;

	} else if (!strcmp(option, "logSyncInterval")) {
		if (1 != sscanf(value, "%hhd", &i8))
			return BAD_VALUE;
		pod->logSyncInterval = i8;

	} else if (!strcmp(option, "logMinDelayReqInterval")) {
		if (1 != sscanf(value, "%hhd", &i8))
			return BAD_VALUE;
		pod->logMinDelayReqInterval = i8;

	} else if (!strcmp(option, "logMinPdelayReqInterval")) {
		if (1 != sscanf(value, "%hhd", &i8))
			return BAD_VALUE;
		pod->logMinPdelayReqInterval = i8;

	} else if (!strcmp(option, "announceReceiptTimeout")) {
		if (1 != sscanf(value, "%hhu", &u8))
			return BAD_VALUE;
		pod->announceReceiptTimeout = u8;

	} else if (!strcmp(option, "transportSpecific")) {
		if (1 != sscanf(value, "%hhx", &u8))
			return BAD_VALUE;
		pod->transportSpecific = u8 << 4;

	} else if (!strcmp(option, "path_trace_enabled")) {
		if (1 != sscanf(value, "%u", &val))
			return BAD_VALUE;
		pod->path_trace_enabled = val ? 1 : 0;

	} else if (!strcmp(option, "follow_up_info")) {
		if (1 != sscanf(value, "%u", &val))
			return BAD_VALUE;
		pod->follow_up_info = val ? 1 : 0;

	} else
		return NOT_PARSED;

	return PARSED_OK;
}

static enum parser_result parse_port_setting(const char *option,
					    const char *value,
					    struct config *cfg,
					    int p)
{
	enum parser_result r;

	r = parse_pod_setting(option, value, &cfg->iface[p].pod);
	if (r != NOT_PARSED)
		return r;

	if (!strcmp(option, "network_transport")) {
		if (!strcasecmp("L2", value))
			cfg->iface[p].transport = TRANS_IEEE_802_3;
		else if (!strcasecmp("UDPv4", value))
			cfg->iface[p].transport = TRANS_UDP_IPV4;
		else if (!strcasecmp("UDPv6", value))
			cfg->iface[p].transport = TRANS_UDP_IPV6;
		else
			return BAD_VALUE;

	} else if (!strcmp(option, "delay_mechanism")) {
		if (!strcasecmp("Auto", value))
			cfg->iface[p].dm = DM_AUTO;
		else if (!strcasecmp("E2E", value))
			cfg->iface[p].dm = DM_E2E;
		else if (!strcasecmp("P2P", value))
			cfg->iface[p].dm = DM_P2P;
		else
			return BAD_VALUE;
	} else
		return NOT_PARSED;

	return PARSED_OK;
}

static enum parser_result parse_global_setting(const char *option,
					       const char *value,
					       struct config *cfg)
{
	double df;
	int i, val, cfg_ignore = cfg->cfg_ignore;
	UInteger16 u16;
	UInteger8 u8;
	unsigned char mac[MAC_LEN];

	struct defaultDS *dds = &cfg->dds;
	struct port_defaults *pod = &cfg->pod;

	enum parser_result r;

	r = parse_pod_setting(option, value, pod);
	if (r != NOT_PARSED)
		return r;

	if (!strcmp(option, "twoStepFlag")) {
		/* TODO - implement one step */
		if (1 != sscanf(value, "%d", &val) || !val)
			return BAD_VALUE;
		dds->twoStepFlag = val ? 1 : 0;

	} else if (!strcmp(option, "slaveOnly")) {
		if (1 != sscanf(value, "%d", &val))
			return BAD_VALUE;
		if (!(cfg_ignore & CFG_IGNORE_SLAVEONLY))
			dds->slaveOnly = val ? 1 : 0;

	} else if (!strcmp(option, "priority1")) {
		if (1 != sscanf(value, "%hhu", &u8))
			return BAD_VALUE;
		dds->priority1 = u8;

	} else if (!strcmp(option, "priority2")) {
		if (1 != sscanf(value, "%hhu", &u8))
			return BAD_VALUE;
		dds->priority2 = u8;

	} else if (!strcmp(option, "domainNumber")) {
		if (1 != sscanf(value, "%hhu", &u8) || !(u8 < 128))
			return BAD_VALUE;
		dds->domainNumber = u8;

	} else if (!strcmp(option, "clockClass")) {
		if (1 != sscanf(value, "%hhu", &u8))
			return BAD_VALUE;
		if (!(cfg_ignore & CFG_IGNORE_SLAVEONLY))
			dds->clockQuality.clockClass = u8;

	} else if (!strcmp(option, "clockAccuracy")) {
		if (1 != sscanf(value, "%hhx", &u8))
			return BAD_VALUE;
		dds->clockQuality.clockAccuracy = u8;

	} else if (!strcmp(option, "offsetScaledLogVariance")) {
		if (1 != sscanf(value, "%hx", &u16))
			return BAD_VALUE;
		dds->clockQuality.offsetScaledLogVariance = u16;

	} else if (!strcmp(option, "free_running")) {
		if (1 != sscanf(value, "%d", &val))
			return BAD_VALUE;
		dds->free_running = val ? 1 : 0;

	} else if (!strcmp(option, "freq_est_interval")) {
		if (1 != sscanf(value, "%d", &val) || !(val >= 0))
			return BAD_VALUE;
		dds->freq_est_interval = val;
		pod->freq_est_interval = val;

	} else if (!strcmp(option, "assume_two_step")) {
		if (1 != sscanf(value, "%u", &val))
			return BAD_VALUE;
		*cfg->assume_two_step = val ? 1 : 0;

	} else if (!strcmp(option, "tx_timestamp_retries")) {
		if (1 != sscanf(value, "%u", &val) || !(val > 0))
			return BAD_VALUE;
		*cfg->tx_timestamp_retries = val;

	} else if (!strcmp(option, "pi_proportional_const")) {
		if (1 != sscanf(value, "%lf", &df) || !(df >= 0.0 && df < 1.0))
			return BAD_VALUE;
		*cfg->pi_proportional_const = df;

	} else if (!strcmp(option, "pi_integral_const")) {
		if (1 != sscanf(value, "%lf", &df) || !(df >= 0.0 && df < 1.0))
			return BAD_VALUE;
		*cfg->pi_integral_const = df;

	} else if (!strcmp(option, "pi_offset_const")) {
		if (1 != sscanf(value, "%lf", &df) || !(df >= 0.0))
			return BAD_VALUE;
		*cfg->pi_offset_const = df;

	} else if (!strcmp(option, "ptp_dst_mac")) {
		if (MAC_LEN != sscanf(value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				      &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
			return BAD_VALUE;
		for (i = 0; i < MAC_LEN; i++)
			cfg->ptp_dst_mac[i] = mac[i];

	} else if (!strcmp(option, "p2p_dst_mac")) {
		if (MAC_LEN != sscanf(value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				      &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
			return BAD_VALUE;
		for (i = 0; i < MAC_LEN; i++)
			cfg->p2p_dst_mac[i] = mac[i];

	} else if (!strcmp(option, "logging_level")) {
		if (1 != sscanf(value, "%d", &val) ||
				!(val >= PRINT_LEVEL_MIN && val <= PRINT_LEVEL_MAX))
			return BAD_VALUE;
		if (!(cfg_ignore & CFG_IGNORE_PRINT_LEVEL)) {
			cfg->print_level = val;
		}

	} else if (!strcmp(option, "verbose")) {
		if (1 != sscanf(value, "%d", &val))
			return BAD_VALUE;
		if (!(cfg_ignore & CFG_IGNORE_VERBOSE))
			cfg->verbose = val ? 1 : 0;

	} else if (!strcmp(option, "use_syslog")) {
		if (1 != sscanf(value, "%d", &val))
			return BAD_VALUE;
		if (!(cfg_ignore & CFG_IGNORE_USE_SYSLOG))
			cfg->use_syslog = val ? 1 : 0;

	} else if (!strcmp(option, "time_stamping")) {
		if (!(cfg_ignore & CFG_IGNORE_TIMESTAMPING)) {
			if (0 == strcasecmp("hardware", value))
				cfg->timestamping = TS_HARDWARE;
			else if (0 == strcasecmp("software", value))
				cfg->timestamping = TS_SOFTWARE;
			else if (0 == strcasecmp("legacy", value))
				cfg->timestamping = TS_LEGACY_HW;
			else
				return BAD_VALUE;
		}

	} else if (!strcmp(option, "delay_mechanism")) {
		if (!(cfg_ignore & CFG_IGNORE_DM)) {
			if (0 == strcasecmp("E2E", value))
				cfg->dm = DM_E2E;
			else if (0 == strcasecmp("P2P", value))
				cfg->dm = DM_P2P;
			else if (0 == strcasecmp("Auto", value))
				cfg->dm = DM_AUTO;
			else
				return BAD_VALUE;
		}

	} else if (!strcmp(option, "network_transport")) {
		if (!(cfg_ignore & CFG_IGNORE_TRANSPORT)) {
			if (!strcasecmp("UDPv4", value))
				cfg->transport = TRANS_UDP_IPV4;
			else if (!strcasecmp("UDPv6", value))
				cfg->transport = TRANS_UDP_IPV6;
			else if (!strcasecmp("L2", value))
				cfg->transport = TRANS_IEEE_802_3;
			else
				return BAD_VALUE;
		}

	} else if (!strcmp(option, "clock_servo")) {
		if (!strcasecmp("pi", value))
			cfg->clock_servo = CLOCK_SERVO_PI;
		else
			return BAD_VALUE;

	} else
		return NOT_PARSED;

	return PARSED_OK;
}

static enum parser_result parse_setting_line(char *line, char **option, char **value)
{
	*option = line;

	while (!isspace(line[0])) {
		if (line[0] == '\0')
			return NOT_PARSED;
		line++;
	}

	while (isspace(line[0])) {
		line[0] = '\0';
		line++;
	}

	*value = line;

	return PARSED_OK;
}

int config_read(char *name, struct config *cfg)
{
	enum config_section current_section = UNKNOWN_SECTION;
	enum parser_result parser_res;
	FILE *fp;
	char buf[1024], *line, *c, *option, *value;
	int current_port, line_num;

	fp = 0 == strncmp(name, "-", 2) ? stdin : fopen(name, "r");

	if (!fp) {
		fprintf(stderr, "failed to open configuration file %s: %m\n", name);
		return -1;
	}

	for (line_num = 1; fgets(buf, sizeof(buf), fp); line_num++) {
		c = buf;

		/* skip whitespace characters */
		while (isspace(*c))
			c++;

		/* ignore empty lines and comments */
		if (*c == '#' || *c == '\n' || *c == '\0')
			continue;

		line = c;

		/* remove trailing whitespace characters and \n */
		c += strlen(line) - 1;
		while (c > line && (*c == '\n' || isspace(*c)))
			*c-- = '\0';

		if (parse_section_line(line, &current_section) == PARSED_OK) {
			if (current_section == PORT_SECTION) {
				char port[17];
				if (1 != sscanf(line, " %16s", port)) {
					fprintf(stderr, "could not parse port name on line %d\n",
							line_num);
					goto parse_error;
				}
				current_port = config_create_interface(port, cfg);
				if (current_port < 0)
					goto parse_error;
			}
			continue;
		}

		switch (current_section) {
		case GLOBAL_SECTION:
		case PORT_SECTION:
			if (parse_setting_line(line, &option, &value)) {
				fprintf(stderr, "could not parse line %d in %s section\n",
						line_num,
						current_section == GLOBAL_SECTION ?
							"global" : cfg->iface[current_port].name);
				goto parse_error;
			}

			if (current_section == GLOBAL_SECTION)
				parser_res = parse_global_setting(option, value, cfg);
			else
				parser_res = parse_port_setting(option, value, cfg, current_port);

			switch (parser_res) {
			case PARSED_OK:
				break;
			case NOT_PARSED:
				fprintf(stderr, "unknown option %s at line %d in %s section\n",
						option, line_num,
						current_section == GLOBAL_SECTION ?
							"global" : cfg->iface[current_port].name);
				goto parse_error;
			case BAD_VALUE:
				fprintf(stderr, "%s is a bad value for option %s at line %d\n",
						value, option, line_num);
				goto parse_error;
			}

			break;
		case UNKNOWN_SECTION:
			fprintf(stderr, "line %d is not in a section\n", line_num);
			goto parse_error;
		default:
			continue;
		}
	}

	fclose(fp);
	return 0;

parse_error:
	fprintf(stderr, "failed to parse configuration file %s\n", name);
	fclose(fp);
	return -2;
}

/* returns the number matching that interface, or -1 on failure */
int config_create_interface(char *name, struct config *cfg)
{
	struct interface *iface;
	int i;

	if (cfg->nports >= MAX_PORTS) {
		fprintf(stderr, "more than %d ports specified\n", MAX_PORTS);
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

	sk_get_ts_info(name, &iface->ts_info);

	cfg->nports++;

	return i;
}
