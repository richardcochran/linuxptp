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
#include <ctype.h>
#include <float.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "ether.h"
#include "print.h"
#include "util.h"

enum config_section {
	GLOBAL_SECTION,
	PORT_SECTION,
	UNKNOWN_SECTION,
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
	unsigned int uval;

	enum parser_result r;

	if (!strcmp(option, "delayAsymmetry")) {
		r = get_ranged_int(value, &val, INT_MIN, INT_MAX);
		if (r != PARSED_OK)
			return r;
		pod->asymmetry = (Integer64) val << 16;

	} else if (!strcmp(option, "logAnnounceInterval")) {
		r = get_ranged_int(value, &val, INT8_MIN, INT8_MAX);
		if (r != PARSED_OK)
			return r;
		pod->logAnnounceInterval = val;

	} else if (!strcmp(option, "logSyncInterval")) {
		r = get_ranged_int(value, &val, INT8_MIN, INT8_MAX);
		if (r != PARSED_OK)
			return r;
		pod->logSyncInterval = val;

	} else if (!strcmp(option, "logMinDelayReqInterval")) {
		r = get_ranged_int(value, &val, INT8_MIN, INT8_MAX);
		if (r != PARSED_OK)
			return r;
		pod->logMinDelayReqInterval = val;

	} else if (!strcmp(option, "logMinPdelayReqInterval")) {
		r = get_ranged_int(value, &val, INT8_MIN, INT8_MAX);
		if (r != PARSED_OK)
			return r;
		pod->logMinPdelayReqInterval = val;

	} else if (!strcmp(option, "announceReceiptTimeout")) {
		r = get_ranged_uint(value, &uval, 2, UINT8_MAX);
		if (r != PARSED_OK)
			return r;
		pod->announceReceiptTimeout = uval;

	} else if (!strcmp(option, "syncReceiptTimeout")) {
		r = get_ranged_uint(value, &uval, 0, UINT8_MAX);
		if (r != PARSED_OK)
			return r;
		pod->syncReceiptTimeout = uval;

	} else if (!strcmp(option, "transportSpecific")) {
		r = get_ranged_uint(value, &uval, 0, 0x0F);
		if (r != PARSED_OK)
			return r;
		pod->transportSpecific = uval << 4;

	} else if (!strcmp(option, "path_trace_enabled")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		pod->path_trace_enabled = val;

	} else if (!strcmp(option, "follow_up_info")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		pod->follow_up_info = val;

	} else if (!strcmp(option, "neighborPropDelayThresh")) {
		r = get_ranged_uint(value, &uval, 0, UINT32_MAX);
		if (r != PARSED_OK)
			return r;
		pod->neighborPropDelayThresh = uval;

	} else if (!strcmp(option, "min_neighbor_prop_delay")) {
		r = get_ranged_int(value, &val, INT_MIN, -1);
		if (r != PARSED_OK)
			return r;
		pod->min_neighbor_prop_delay = val;

	} else if (!strcmp(option, "fault_badpeernet_interval")) {
		pod->flt_interval_pertype[FT_BAD_PEER_NETWORK].type = FTMO_LINEAR_SECONDS;
		if (!strcasecmp("ASAP", value)) {
			pod->flt_interval_pertype[FT_BAD_PEER_NETWORK].val = 0;
		} else {
			r = get_ranged_int(value, &val, INT32_MIN, INT32_MAX);
			if (r != PARSED_OK)
				return r;
			pod->flt_interval_pertype[FT_BAD_PEER_NETWORK].val = val;
		}

	} else if (!strcmp(option, "fault_reset_interval")) {
		pod->flt_interval_pertype[FT_UNSPECIFIED].type = FTMO_LOG2_SECONDS;
		if (!strcasecmp("ASAP", value)) {
			pod->flt_interval_pertype[FT_UNSPECIFIED].val = FRI_ASAP;
		} else {
			r = get_ranged_int(value, &val, INT8_MIN, INT8_MAX);
			if (r != PARSED_OK)
				return r;
			pod->flt_interval_pertype[FT_UNSPECIFIED].val = val;
		}

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
	int val;

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

	} else if (!strcmp(option, "delay_filter")) {
		if (!strcasecmp("moving_average", value))
			cfg->iface[p].delay_filter = FILTER_MOVING_AVERAGE;
		else if (!strcasecmp("moving_median", value))
			cfg->iface[p].delay_filter = FILTER_MOVING_MEDIAN;
		else
			return BAD_VALUE;

	} else if (!strcmp(option, "delay_filter_length")) {
		r = get_ranged_int(value, &val, 1, INT_MAX);
		if (r != PARSED_OK)
			return r;
		cfg->iface[p].delay_filter_length = val;

	} else
		return NOT_PARSED;

	return PARSED_OK;
}

static int count_char(const char *str, char c)
{
	int num = 0;
	char s;
	while ((s = *(str++))) {
		if (s == c)
			num++;
	}
	return num;
}

static enum parser_result parse_global_setting(const char *option,
					       const char *value,
					       struct config *cfg)
{
	double df;
	int i, val, cfg_ignore = cfg->cfg_ignore;
	unsigned int uval;
	unsigned char mac[MAC_LEN];
	unsigned char oui[OUI_LEN];

	struct defaultDS *dds = &cfg->dds.dds;
	struct port_defaults *pod = &cfg->pod;

	enum parser_result r;

	r = parse_pod_setting(option, value, pod);
	if (r != NOT_PARSED)
		return r;

	if (!strcmp(option, "twoStepFlag")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		if (val)
			dds->flags |=  DDS_TWO_STEP_FLAG;
		else
			dds->flags &= ~DDS_TWO_STEP_FLAG;

	} else if (!strcmp(option, "slaveOnly")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		if (!(cfg_ignore & CFG_IGNORE_SLAVEONLY)) {
			if (val)
				dds->flags |=  DDS_SLAVE_ONLY;
			else
				dds->flags &= ~DDS_SLAVE_ONLY;
		}

	} else if (!strcmp(option, "gmCapable")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		cfg->dds.grand_master_capable = val;

	} else if (!strcmp(option, "priority1")) {
		r = get_ranged_uint(value, &uval, 0, UINT8_MAX);
		if (r != PARSED_OK)
			return r;
		dds->priority1 = uval;

	} else if (!strcmp(option, "priority2")) {
		r = get_ranged_uint(value, &uval, 0, UINT8_MAX);
		if (r != PARSED_OK)
			return r;
		dds->priority2 = uval;

	} else if (!strcmp(option, "domainNumber")) {
		r = get_ranged_uint(value, &uval, 0, 127);
		if (r != PARSED_OK)
			return r;
		dds->domainNumber = uval;

	} else if (!strcmp(option, "clockClass")) {
		r = get_ranged_uint(value, &uval, 0, UINT8_MAX);
		if (r != PARSED_OK)
			return r;
		if (!(cfg_ignore & CFG_IGNORE_SLAVEONLY))
			dds->clockQuality.clockClass = uval;

	} else if (!strcmp(option, "clockAccuracy")) {
		r = get_ranged_uint(value, &uval, 0, UINT8_MAX);
		if (r != PARSED_OK)
			return r;
		dds->clockQuality.clockAccuracy = uval;

	} else if (!strcmp(option, "offsetScaledLogVariance")) {
		r = get_ranged_uint(value, &uval, 0, UINT16_MAX);
		if (r != PARSED_OK)
			return r;
		dds->clockQuality.offsetScaledLogVariance = uval;

	} else if (!strcmp(option, "free_running")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		cfg->dds.free_running = val;

	} else if (!strcmp(option, "freq_est_interval")) {
		r = get_ranged_int(value, &val, 0, INT_MAX);
		if (r != PARSED_OK)
			return r;
		cfg->dds.freq_est_interval = val;
		pod->freq_est_interval = val;

	} else if (!strcmp(option, "assume_two_step")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		*cfg->assume_two_step = val;

	} else if (!strcmp(option, "tx_timestamp_timeout")) {
		r = get_ranged_int(value, &val, 1, INT_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->tx_timestamp_timeout = val;

	} else if (!strcmp(option, "check_fup_sync")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		*cfg->check_fup_sync = val;

	} else if (!strcmp(option, "pi_proportional_const")) {
		r = get_ranged_double(value, &df, 0.0, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_proportional_const = df;

	} else if (!strcmp(option, "pi_integral_const")) {
		r = get_ranged_double(value, &df, 0.0, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_integral_const = df;

	} else if (!strcmp(option, "pi_proportional_scale")) {
		r = get_ranged_double(value, &df, 0.0, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_proportional_scale = df;

	} else if (!strcmp(option, "pi_proportional_exponent")) {
		r = get_ranged_double(value, &df, -DBL_MAX, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_proportional_exponent = df;

	} else if (!strcmp(option, "pi_proportional_norm_max")) {
		r = get_ranged_double(value, &df, DBL_MIN, 1.0);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_proportional_norm_max = df;

	} else if (!strcmp(option, "pi_integral_scale")) {
		r = get_ranged_double(value, &df, 0.0, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_integral_scale = df;

	} else if (!strcmp(option, "pi_integral_exponent")) {
		r = get_ranged_double(value, &df, -DBL_MAX, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_integral_exponent = df;

	} else if (!strcmp(option, "pi_integral_norm_max")) {
		r = get_ranged_double(value, &df, DBL_MIN, 2.0);
		if (r != PARSED_OK)
			return r;
		*cfg->pi_integral_norm_max = df;

	} else if (!strcmp(option, "step_threshold") ||
		   !strcmp(option, "pi_offset_const")) {
		r = get_ranged_double(value, &df, 0.0, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->step_threshold = df;

	} else if (!strcmp(option, "first_step_threshold") ||
		   !strcmp(option, "pi_f_offset_const")) {
		r = get_ranged_double(value, &df, 0.0, DBL_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->first_step_threshold = df;

	} else if (!strcmp(option, "max_frequency") ||
		   !strcmp(option, "pi_max_frequency")) {
		r = get_ranged_int(value, &val, 0, INT_MAX);
		if (r != PARSED_OK)
			return r;
		*cfg->max_frequency = val;

	} else if (!strcmp(option, "sanity_freq_limit")) {
		r = get_ranged_int(value, &val, 0, INT_MAX);
		if (r != PARSED_OK)
			return r;
		cfg->dds.sanity_freq_limit = val;

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

	} else if (!strcmp(option, "udp6_scope")) {
		r = get_ranged_uint(value, &uval, 0x00, 0x0F);
		if (r != PARSED_OK)
			return r;
		*cfg->udp6_scope = uval;

	} else if (!strcmp(option, "uds_address")) {
		if (strlen(value) > MAX_IFNAME_SIZE)
			return OUT_OF_RANGE;
		strncpy(cfg->uds_address, value, MAX_IFNAME_SIZE);

	} else if (!strcmp(option, "logging_level")) {
		r = get_ranged_int(value, &val,
				   PRINT_LEVEL_MIN, PRINT_LEVEL_MAX);
		if (r != PARSED_OK)
			return r;
		if (!(cfg_ignore & CFG_IGNORE_PRINT_LEVEL)) {
			cfg->print_level = val;
		}

	} else if (!strcmp(option, "verbose")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		if (!(cfg_ignore & CFG_IGNORE_VERBOSE))
			cfg->verbose = val;

	} else if (!strcmp(option, "use_syslog")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		if (!(cfg_ignore & CFG_IGNORE_USE_SYSLOG))
			cfg->use_syslog = val;

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
		else if (!strcasecmp("linreg", value))
			cfg->clock_servo = CLOCK_SERVO_LINREG;
		else
			return BAD_VALUE;

	} else if (!strcmp(option, "productDescription")) {
		if (count_char(value, ';') != 2)
			return BAD_VALUE;
		if (static_ptp_text_set(&cfg->dds.clock_desc.productDescription, value) != 0)
			return BAD_VALUE;

	} else if (!strcmp(option, "revisionData")) {
		if (count_char(value, ';') != 2)
			return BAD_VALUE;
		if (static_ptp_text_set(&cfg->dds.clock_desc.revisionData, value) != 0)
			return BAD_VALUE;

	} else if (!strcmp(option, "userDescription")) {
		if (static_ptp_text_set(&cfg->dds.clock_desc.userDescription, value) != 0)
			return BAD_VALUE;

	} else if (!strcmp(option, "manufacturerIdentity")) {
		if (OUI_LEN != sscanf(value, "%hhx:%hhx:%hhx",
				      &oui[0], &oui[1], &oui[2]))
			return BAD_VALUE;
		for (i = 0; i < OUI_LEN; i++)
			cfg->dds.clock_desc.manufacturerIdentity[i] = oui[i];

	} else if (!strcmp(option, "summary_interval")) {
		r = get_ranged_int(value, &val, INT_MIN, INT_MAX);
		if (r != PARSED_OK)
			return r;
		cfg->dds.stats_interval = val;

	} else if (!strcmp(option, "kernel_leap")) {
		r = get_ranged_int(value, &val, 0, 1);
		if (r != PARSED_OK)
			return r;
		cfg->dds.kernel_leap = val;

	} else if (!strcmp(option, "timeSource")) {
		r = get_ranged_int(value, &val, 0x10, 0xfe);
		if (r != PARSED_OK)
			return r;
		cfg->dds.time_source = val;

	} else if (!strcmp(option, "delay_filter")) {
		if (!strcasecmp("moving_average", value))
			cfg->dds.delay_filter = FILTER_MOVING_AVERAGE;
		else if (!strcasecmp("moving_median", value))
			cfg->dds.delay_filter = FILTER_MOVING_MEDIAN;
		else
			return BAD_VALUE;

	} else if (!strcmp(option, "delay_filter_length")) {
		r = get_ranged_int(value, &val, 1, INT_MAX);
		if (r != PARSED_OK)
			return r;
		cfg->dds.delay_filter_length = val;

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
	int current_port = 0, line_num;

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
			case MALFORMED:
				fprintf(stderr, "%s is a malformed value for option %s at line %d\n",
						value, option, line_num);
				goto parse_error;
			case OUT_OF_RANGE:
				fprintf(stderr, "%s is an out of range value for option %s at line %d\n",
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

	iface->delay_filter = cfg->dds.delay_filter;
	iface->delay_filter_length = cfg->dds.delay_filter_length;

	cfg->nports++;

	return i;
}
