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
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "ether.h"
#include "hash.h"
#include "print.h"
#include "util.h"

enum config_section {
	GLOBAL_SECTION,
	PORT_SECTION,
	UNKNOWN_SECTION,
};

enum config_type {
	CFG_TYPE_INT,
	CFG_TYPE_DOUBLE,
	CFG_TYPE_ENUM,
	CFG_TYPE_STRING,
};

struct config_enum {
	const char *label;
	int value;
};

typedef union {
	int i;
	double d;
	char *s;
} any_t;

#define CONFIG_LABEL_SIZE 32

#define CFG_ITEM_STATIC (1 << 0) /* statically allocated, not to be freed */
#define CFG_ITEM_LOCKED (1 << 1) /* command line value, may not be changed */
#define CFG_ITEM_PORT   (1 << 2) /* item may appear in port sections */
#define CFG_ITEM_DYNSTR (1 << 4) /* string value dynamically allocated */

struct config_item {
	char label[CONFIG_LABEL_SIZE];
	enum config_type type;
	struct config_enum *tab;
	unsigned int flags;
	any_t val;
	any_t min;
	any_t max;
};

#define N_CONFIG_ITEMS (sizeof(config_tab) / sizeof(config_tab[0]))

#define CONFIG_ITEM_DBL(_label, _port, _default, _min, _max) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_DOUBLE,			\
	.flags	= _port ? CFG_ITEM_PORT : 0,		\
	.val.d	= _default,				\
	.min.d	= _min,					\
	.max.d	= _max,					\
}
#define CONFIG_ITEM_ENUM(_label, _port, _default, _table) { \
	.label	= _label,				\
	.type	= CFG_TYPE_ENUM,			\
	.flags	= _port ? CFG_ITEM_PORT : 0,		\
	.tab	= _table,				\
	.val.i	= _default,				\
}
#define CONFIG_ITEM_INT(_label, _port, _default, _min, _max) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_INT,				\
	.flags	= _port ? CFG_ITEM_PORT : 0,		\
	.val.i	= _default,				\
	.min.i	= _min,					\
	.max.i	= _max,					\
}
#define CONFIG_ITEM_STRING(_label, _port, _default) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_STRING,			\
	.flags	= _port ? CFG_ITEM_PORT : 0,		\
	.val.s	= _default,				\
}

#define GLOB_ITEM_DBL(label, _default, min, max) \
	CONFIG_ITEM_DBL(label, 0, _default, min, max)

#define GLOB_ITEM_ENU(label, _default, table) \
	CONFIG_ITEM_ENUM(label, 0, _default, table)

#define GLOB_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, 0, _default, min, max)

#define GLOB_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, 0, _default)

#define PORT_ITEM_DBL(label, _default, min, max) \
	CONFIG_ITEM_DBL(label, 1, _default, min, max)

#define PORT_ITEM_ENU(label, _default, table) \
	CONFIG_ITEM_ENUM(label, 1, _default, table)

#define PORT_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, 1, _default, min, max)

#define PORT_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, 1, _default)

static struct config_enum clock_servo_enu[] = {
	{ "pi",     CLOCK_SERVO_PI     },
	{ "linreg", CLOCK_SERVO_LINREG },
	{ "ntpshm", CLOCK_SERVO_NTPSHM },
	{ "nullf",  CLOCK_SERVO_NULLF  },
	{ NULL, 0 },
};

static struct config_enum delay_filter_enu[] = {
	{ "moving_average", FILTER_MOVING_AVERAGE },
	{ "moving_median",  FILTER_MOVING_MEDIAN  },
	{ NULL, 0 },
};

static struct config_enum delay_mech_enu[] = {
	{ "Auto", DM_AUTO },
	{ "E2E",  DM_E2E },
	{ "P2P",  DM_P2P },
	{ NULL, 0 },
};

static struct config_enum nw_trans_enu[] = {
	{ "L2",    TRANS_IEEE_802_3 },
	{ "UDPv4", TRANS_UDP_IPV4   },
	{ "UDPv6", TRANS_UDP_IPV6   },
	{ NULL, 0 },
};

static struct config_enum timestamping_enu[] = {
	{ "hardware", TS_HARDWARE  },
	{ "software", TS_SOFTWARE  },
	{ "legacy",   TS_LEGACY_HW },
	{ NULL, 0 },
};

static struct config_enum tsproc_enu[] = {
	{ "filter",        TSPROC_FILTER        },
	{ "raw",           TSPROC_RAW           },
	{ "filter_weight", TSPROC_FILTER_WEIGHT },
	{ "raw_weight",    TSPROC_RAW_WEIGHT    },
	{ NULL, 0 },
};

struct config_item config_tab[] = {
	PORT_ITEM_INT("announceReceiptTimeout", 3, 2, UINT8_MAX),
	GLOB_ITEM_INT("assume_two_step", 0, 0, 1),
	PORT_ITEM_INT("boundary_clock_jbod", 0, 0, 1),
	GLOB_ITEM_INT("check_fup_sync", 0, 0, 1),
	GLOB_ITEM_INT("clockAccuracy", 0xfe, 0, UINT8_MAX),
	GLOB_ITEM_INT("clockClass", 248, 0, UINT8_MAX),
	GLOB_ITEM_ENU("clock_servo", CLOCK_SERVO_PI, clock_servo_enu),
	PORT_ITEM_INT("delayAsymmetry", 0, INT_MIN, INT_MAX),
	PORT_ITEM_ENU("delay_filter", FILTER_MOVING_MEDIAN, delay_filter_enu),
	PORT_ITEM_INT("delay_filter_length", 10, 1, INT_MAX),
	PORT_ITEM_ENU("delay_mechanism", DM_E2E, delay_mech_enu),
	GLOB_ITEM_INT("domainNumber", 0, 0, 127),
	PORT_ITEM_INT("egressLatency", 0, INT_MIN, INT_MAX),
	PORT_ITEM_INT("fault_badpeernet_interval", 16, INT32_MIN, INT32_MAX),
	PORT_ITEM_INT("fault_reset_interval", 4, INT8_MIN, INT8_MAX),
	GLOB_ITEM_DBL("first_step_threshold", 0.00002, 0.0, DBL_MAX),
	PORT_ITEM_INT("follow_up_info", 0, 0, 1),
	GLOB_ITEM_INT("free_running", 0, 0, 1),
	PORT_ITEM_INT("freq_est_interval", 1, 0, INT_MAX),
	GLOB_ITEM_INT("gmCapable", 1, 0, 1),
	PORT_ITEM_INT("hybrid_e2e", 0, 0, 1),
	PORT_ITEM_INT("ingressLatency", 0, INT_MIN, INT_MAX),
	GLOB_ITEM_INT("kernel_leap", 1, 0, 1),
	PORT_ITEM_INT("logAnnounceInterval", 1, INT8_MIN, INT8_MAX),
	PORT_ITEM_INT("logMinDelayReqInterval", 0, INT8_MIN, INT8_MAX),
	PORT_ITEM_INT("logMinPdelayReqInterval", 0, INT8_MIN, INT8_MAX),
	PORT_ITEM_INT("logSyncInterval", 0, INT8_MIN, INT8_MAX),
	GLOB_ITEM_INT("logging_level", LOG_INFO, PRINT_LEVEL_MIN, PRINT_LEVEL_MAX),
	GLOB_ITEM_STR("manufacturerIdentity", "00:00:00"),
	GLOB_ITEM_INT("max_frequency", 900000000, 0, INT_MAX),
	PORT_ITEM_INT("min_neighbor_prop_delay", -20000000, INT_MIN, -1),
	PORT_ITEM_INT("neighborPropDelayThresh", 20000000, 0, INT_MAX),
	PORT_ITEM_ENU("network_transport", TRANS_UDP_IPV4, nw_trans_enu),
	GLOB_ITEM_INT("ntpshm_segment", 0, INT_MIN, INT_MAX),
	GLOB_ITEM_INT("offsetScaledLogVariance", 0xffff, 0, UINT16_MAX),
	PORT_ITEM_INT("path_trace_enabled", 0, 0, 1),
	GLOB_ITEM_DBL("pi_integral_const", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_DBL("pi_integral_exponent", 0.4, -DBL_MAX, DBL_MAX),
	GLOB_ITEM_DBL("pi_integral_norm_max", 0.3, DBL_MIN, 2.0),
	GLOB_ITEM_DBL("pi_integral_scale", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_DBL("pi_proportional_const", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_DBL("pi_proportional_exponent", -0.3, -DBL_MAX, DBL_MAX),
	GLOB_ITEM_DBL("pi_proportional_norm_max", 0.7, DBL_MIN, 1.0),
	GLOB_ITEM_DBL("pi_proportional_scale", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_INT("priority1", 128, 0, UINT8_MAX),
	GLOB_ITEM_INT("priority2", 128, 0, UINT8_MAX),
	GLOB_ITEM_STR("productDescription", ";;"),
	PORT_ITEM_STR("ptp_dst_mac", "01:1B:19:00:00:00"),
	PORT_ITEM_STR("p2p_dst_mac", "01:80:C2:00:00:0E"),
	GLOB_ITEM_STR("revisionData", ";;"),
	GLOB_ITEM_INT("sanity_freq_limit", 200000000, 0, INT_MAX),
	GLOB_ITEM_INT("slaveOnly", 0, 0, 1),
	GLOB_ITEM_DBL("step_threshold", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_INT("summary_interval", 0, INT_MIN, INT_MAX),
	PORT_ITEM_INT("syncReceiptTimeout", 0, 0, UINT8_MAX),
	GLOB_ITEM_INT("timeSource", INTERNAL_OSCILLATOR, 0x10, 0xfe),
	GLOB_ITEM_ENU("time_stamping", TS_HARDWARE, timestamping_enu),
	PORT_ITEM_INT("transportSpecific", 0, 0, 0x0F),
	PORT_ITEM_ENU("tsproc_mode", TSPROC_FILTER, tsproc_enu),
	GLOB_ITEM_INT("twoStepFlag", 1, 0, 1),
	GLOB_ITEM_INT("tx_timestamp_timeout", 1, 1, INT_MAX),
	PORT_ITEM_INT("udp_ttl", 1, 1, 255),
	PORT_ITEM_INT("udp6_scope", 0x0E, 0x00, 0x0F),
	GLOB_ITEM_STR("uds_address", "/var/run/ptp4l"),
	GLOB_ITEM_INT("use_syslog", 1, 0, 1),
	GLOB_ITEM_STR("userDescription", ""),
	GLOB_ITEM_INT("verbose", 0, 0, 1),
};

static enum parser_result
parse_fault_interval(struct config *cfg, const char *section,
		     const char *option, const char *value);

static struct config_item *config_section_item(struct config *cfg,
					       const char *section,
					       const char *name)
{
	char buf[CONFIG_LABEL_SIZE + MAX_IFNAME_SIZE];

	snprintf(buf, sizeof(buf), "%s.%s", section, name);
	return hash_lookup(cfg->htab, buf);
}

static struct config_item *config_global_item(struct config *cfg,
					      const char *name)
{
	return config_section_item(cfg, "global", name);
}

static struct config_item *config_find_item(struct config *cfg,
					    const char *section,
					    const char *name)
{
	struct config_item *ci;
	if (section) {
		ci = config_section_item(cfg, section, name);
		if (ci) {
			return ci;
		}
	}
	return config_global_item(cfg, name);
}

static struct config_item *config_item_alloc(struct config *cfg,
					     const char *section,
					     const char *name,
					     enum config_type type)
{
	struct config_item *ci;
	char buf[CONFIG_LABEL_SIZE + MAX_IFNAME_SIZE];

	ci = calloc(1, sizeof(*ci));
	if (!ci) {
		fprintf(stderr, "low memory\n");
		return NULL;
	}
	strncpy(ci->label, name, CONFIG_LABEL_SIZE - 1);
	ci->type = type;

	snprintf(buf, sizeof(buf), "%s.%s", section, ci->label);
	if (hash_insert(cfg->htab, buf, ci)) {
		fprintf(stderr, "low memory or duplicate item %s\n", name);
		free(ci);
		return NULL;
	}

	return ci;
}

static void config_item_free(void *ptr)
{
	struct config_item *ci = ptr;
	if (ci->type == CFG_TYPE_STRING && ci->flags & CFG_ITEM_DYNSTR)
		free(ci->val.s);
	if (ci->flags & CFG_ITEM_STATIC)
		return;
	free(ci);
}

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

static enum parser_result parse_item(struct config *cfg,
				     const char *section,
				     const char *option,
				     const char *value)
{
	enum parser_result r;
	struct config_item *cgi, *dst;
	struct config_enum *cte;
	double df;
	int val;

	r = parse_fault_interval(cfg, section, option, value);
	if (r != NOT_PARSED)
		return r;

	r = BAD_VALUE;

	/* If there is no default value, then the option is bogus. */
	cgi = config_global_item(cfg, option);
	if (!cgi) {
		return NOT_PARSED;
	}

	switch (cgi->type) {
	case CFG_TYPE_INT:
		r = get_ranged_int(value, &val, cgi->min.i, cgi->max.i);
		break;
	case CFG_TYPE_DOUBLE:
		r = get_ranged_double(value, &df, cgi->min.d, cgi->max.d);
		break;
	case CFG_TYPE_ENUM:
		for (cte = cgi->tab; cte->label; cte++) {
			if (!strcasecmp(cte->label, value)) {
				val = cte->value;
				r = PARSED_OK;
				break;
			}
		}
		break;
	case CFG_TYPE_STRING:
		r = PARSED_OK;
		break;
	}
	if (r != PARSED_OK) {
		return r;
	}

	if (section) {
		if (!(cgi->flags & CFG_ITEM_PORT)) {
			return NOT_PARSED;
		}
		/* Create or update this port specific item. */
		dst = config_section_item(cfg, section, option);
		if (!dst) {
			dst = config_item_alloc(cfg, section, option, cgi->type);
			if (!dst) {
				return NOT_PARSED;
			}
		}
	} else if (cgi->flags & CFG_ITEM_LOCKED) {
		/* This global option was set on the command line. */
		return PARSED_OK;
	} else {
		/* Update the global default value. */
		dst = cgi;
	}

	switch (dst->type) {
	case CFG_TYPE_INT:
	case CFG_TYPE_ENUM:
		dst->val.i = val;
		break;
	case CFG_TYPE_DOUBLE:
		dst->val.d = df;
		break;
	case CFG_TYPE_STRING:
		if (dst->flags & CFG_ITEM_DYNSTR) {
			free(dst->val.s);
		}
		dst->val.s = strdup(value);
		if (!dst->val.s) {
			pr_err("low memory");
			return NOT_PARSED;
		}
		dst->flags |= CFG_ITEM_DYNSTR;
		break;
	}
	return PARSED_OK;
}

static enum parser_result parse_fault_interval(struct config *cfg,
					       const char *section,
					       const char *option,
					       const char *value)
{
	int i, val;
	const char *str, *fault_options[2] = {
		"fault_badpeernet_interval",
		"fault_reset_interval",
	};
	int fault_values[2] = {
		0, FRI_ASAP,
	};

	if (strcasecmp("ASAP", value)) {
		return NOT_PARSED;
	}
	for (i = 0; i < 2; i++) {
		str = fault_options[i];
		val = fault_values[i];
		if (!strcmp(option, str)) {
			if (config_set_section_int(cfg, section, str, val)) {
				pr_err("bug: failed to set option %s!", option);
				exit(-1);
			}
			return PARSED_OK;
		}
	}
	return NOT_PARSED;
}

static enum parser_result parse_setting_line(char *line,
					     const char **option,
					     const char **value)
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

static void check_deprecated_options(const char **option)
{
	const char *new_option = NULL;

	if (!strcmp(*option, "pi_offset_const")) {
		new_option = "step_threshold";
	} else if (!strcmp(*option, "pi_f_offset_const")) {
		new_option = "first_step_threshold";
	} else if (!strcmp(*option, "pi_max_frequency")) {
		new_option = "max_frequency";
	}

	if (new_option) {
		fprintf(stderr, "option %s is deprecated, please use %s instead\n",
				*option, new_option);
		*option = new_option;
	}
}

int config_read(char *name, struct config *cfg)
{
	enum config_section current_section = UNKNOWN_SECTION;
	enum parser_result parser_res;
	FILE *fp;
	char buf[1024], *line, *c;
	const char *option, *value;
	struct interface *current_port = NULL;
	int line_num;

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
				if (!current_port)
					goto parse_error;
				config_init_interface(current_port, cfg);
			}
			continue;
		}

		if (current_section == UNKNOWN_SECTION) {
			fprintf(stderr, "line %d is not in a section\n", line_num);
			goto parse_error;
		}

		if (parse_setting_line(line, &option, &value)) {
			fprintf(stderr, "could not parse line %d in %s section\n",
				line_num, current_section == GLOBAL_SECTION ?
				"global" : current_port->name);
			goto parse_error;
		}

		check_deprecated_options(&option);

		parser_res = parse_item(cfg, current_section == GLOBAL_SECTION ?
					NULL : current_port->name, option, value);

		switch (parser_res) {
		case PARSED_OK:
			break;
		case NOT_PARSED:
			fprintf(stderr, "unknown option %s at line %d in %s section\n",
				option, line_num,
				current_section == GLOBAL_SECTION ? "global" :
				current_port->name);
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
	}

	fclose(fp);
	return 0;

parse_error:
	fprintf(stderr, "failed to parse configuration file %s\n", name);
	fclose(fp);
	return -2;
}

struct interface *config_create_interface(char *name, struct config *cfg)
{
	struct interface *iface;

	/* only create each interface once (by name) */
	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		if (0 == strncmp(name, iface->name, MAX_IFNAME_SIZE))
			return iface;
	}

	iface = calloc(1, sizeof(struct interface));
	if (!iface) {
		fprintf(stderr, "cannot allocate memory for a port\n");
		return NULL;
	}

	strncpy(iface->name, name, MAX_IFNAME_SIZE);
	STAILQ_INSERT_TAIL(&cfg->interfaces, iface, list);
	return iface;
}

void config_init_interface(struct interface *iface, struct config *cfg)
{
	sk_get_ts_info(iface->name, &iface->ts_info);
}

struct config *config_create(void)
{
	char buf[CONFIG_LABEL_SIZE + 8];
	struct config_item *ci;
	struct config *cfg;
	int i;

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg) {
		return NULL;
	}
	STAILQ_INIT(&cfg->interfaces);

	cfg->htab = hash_create();
	if (!cfg->htab) {
		free(cfg);
		return NULL;
	}

	/* Populate the hash table with global defaults. */
	for (i = 0; i < N_CONFIG_ITEMS; i++) {
		ci = &config_tab[i];
		ci->flags |= CFG_ITEM_STATIC;
		snprintf(buf, sizeof(buf), "global.%s", ci->label);
		if (hash_insert(cfg->htab, buf, ci)) {
			fprintf(stderr, "duplicate item %s\n", ci->label);
			goto fail;
		}
	}

	/* Perform a Built In Self Test.*/
	for (i = 0; i < N_CONFIG_ITEMS; i++) {
		ci = &config_tab[i];
		ci = config_global_item(cfg, ci->label);
		if (ci != &config_tab[i]) {
			fprintf(stderr, "config BIST failed at %s\n",
				config_tab[i].label);
			goto fail;
		}
	}
	return cfg;
fail:
	hash_destroy(cfg->htab, NULL);
	free(cfg);
	return NULL;
}

void config_destroy(struct config *cfg)
{
	struct interface *iface;

	while ((iface = STAILQ_FIRST(&cfg->interfaces))) {
		STAILQ_REMOVE_HEAD(&cfg->interfaces, list);
		free(iface);
	}
	hash_destroy(cfg->htab, config_item_free);
	free(cfg);
}

double config_get_double(struct config *cfg, const char *section,
			 const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci || ci->type != CFG_TYPE_DOUBLE) {
		pr_err("bug: config option %s missing or invalid!", option);
		exit(-1);
	}
	pr_debug("config item %s.%s is %f", section, option, ci->val.d);
	return ci->val.d;
}

int config_get_int(struct config *cfg, const char *section, const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci) {
		pr_err("bug: config option %s missing!", option);
		exit(-1);
	}
	switch (ci->type) {
	case CFG_TYPE_DOUBLE:
	case CFG_TYPE_STRING:
		pr_err("bug: config option %s type mismatch!", option);
		exit(-1);
	case CFG_TYPE_INT:
	case CFG_TYPE_ENUM:
		break;
	}
	pr_debug("config item %s.%s is %d", section, option, ci->val.i);
	return ci->val.i;
}

char *config_get_string(struct config *cfg, const char *section,
			const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci || ci->type != CFG_TYPE_STRING) {
		pr_err("bug: config option %s missing or invalid!", option);
		exit(-1);
	}
	pr_debug("config item %s.%s is '%s'", section, option, ci->val.s);
	return ci->val.s;
}

int config_set_double(struct config *cfg, const char *option, double val)
{
	struct config_item *ci = config_find_item(cfg, NULL, option);

	if (!ci || ci->type != CFG_TYPE_DOUBLE) {
		pr_err("bug: config option %s missing or invalid!", option);
		return -1;
	}
	ci->flags |= CFG_ITEM_LOCKED;
	ci->val.d = val;
	pr_debug("locked item global.%s as %f", option, ci->val.d);
	return 0;
}

int config_set_section_int(struct config *cfg, const char *section,
			   const char *option, int val)
{
	struct config_item *cgi, *dst;

	cgi = config_find_item(cfg, NULL, option);
	if (!cgi) {
		pr_err("bug: config option %s missing!", option);
		return -1;
	}
	switch (cgi->type) {
	case CFG_TYPE_DOUBLE:
	case CFG_TYPE_STRING:
		pr_err("bug: config option %s type mismatch!", option);
		return -1;
	case CFG_TYPE_INT:
	case CFG_TYPE_ENUM:
		break;
	}
	if (!section) {
		cgi->flags |= CFG_ITEM_LOCKED;
		cgi->val.i = val;
		pr_debug("locked item global.%s as %d", option, cgi->val.i);
		return 0;
	}
	/* Create or update this port specific item. */
	dst = config_section_item(cfg, section, option);
	if (!dst) {
		dst = config_item_alloc(cfg, section, option, cgi->type);
		if (!dst) {
			return -1;
		}
	}
	dst->val.i = val;
	pr_debug("section item %s.%s now %d", section, option, dst->val.i);
	return 0;
}

int config_set_string(struct config *cfg, const char *option,
		      const char *val)
{
	struct config_item *ci = config_find_item(cfg, NULL, option);

	if (!ci || ci->type != CFG_TYPE_STRING) {
		pr_err("bug: config option %s missing or invalid!", option);
		return -1;
	}
	ci->flags |= CFG_ITEM_LOCKED;
	if (ci->flags & CFG_ITEM_DYNSTR) {
		free(ci->val.s);
	}
	ci->val.s = strdup(val);
	if (!ci->val.s) {
		pr_err("low memory");
		return -1;
	}
	ci->flags |= CFG_ITEM_DYNSTR;
	pr_debug("locked item global.%s as '%s'", option, ci->val.s);
	return 0;
}
