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
#include <linux/ptp_clock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "as_capable.h"
#include "bmc.h"
#include "clock.h"
#include "config.h"
#include "ether.h"
#include "hash.h"
#include "power_profile.h"
#include "print.h"
#include "util.h"

#define UDS_FILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) /*0660*/
#define UDS_RO_FILEMODE (UDS_FILEMODE|S_IROTH|S_IWOTH) /*0666*/

struct interface {
	STAILQ_ENTRY(interface) list;
};

enum config_section {
	GLOBAL_SECTION,
	UC_MTAB_SECTION,
	PORT_SECTION,
	UNKNOWN_SECTION,
};

enum config_type {
	CFG_TYPE_INT,
	CFG_TYPE_DOUBLE,
	CFG_TYPE_ENUM,
	CFG_TYPE_STRING,
	CFG_TYPE_UINT,
};

struct config_enum {
	const char *label;
	int value;
};

typedef union {
	int i;
	double d;
	char *s;
	uint32_t u;
} any_t;

#define CONFIG_LABEL_SIZE 64

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
#define CONFIG_ITEM_UINT(_label, _port, _default, _min, _max) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_UINT,			\
	.flags	= _port ? CFG_ITEM_PORT : 0,		\
	.val.u	= _default,				\
	.min.u	= _min,					\
	.max.u	= _max,					\
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

#define GLOB_ITEM_UIN(label, _default, min, max) \
	CONFIG_ITEM_UINT(label, 0, _default, min, max)

#define GLOB_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, 0, _default)

#define PORT_ITEM_DBL(label, _default, min, max) \
	CONFIG_ITEM_DBL(label, 1, _default, min, max)

#define PORT_ITEM_ENU(label, _default, table) \
	CONFIG_ITEM_ENUM(label, 1, _default, table)

#define PORT_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, 1, _default, min, max)

#define PORT_ITEM_UIN(label, _default, min, max) \
	CONFIG_ITEM_UINT(label, 1, _default, min, max)

#define PORT_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, 1, _default)

static struct config_enum clock_servo_enu[] = {
	{ "pi",     CLOCK_SERVO_PI     },
	{ "linreg", CLOCK_SERVO_LINREG },
	{ "ntpshm", CLOCK_SERVO_NTPSHM },
	{ "nullf",  CLOCK_SERVO_NULLF  },
	{ "refclock_sock", CLOCK_SERVO_REFCLOCK_SOCK },
	{ NULL, 0 },
};

static struct config_enum clock_type_enu[] = {
	{ "OC",      CLOCK_TYPE_ORDINARY },
	{ "BC",      CLOCK_TYPE_BOUNDARY },
	{ "P2P_TC",  CLOCK_TYPE_P2P      },
	{ "E2E_TC",  CLOCK_TYPE_E2E      },
	{ NULL, 0 },
};

static struct config_enum dataset_comp_enu[] = {
	{ "ieee1588", DS_CMP_IEEE1588 },
	{ "G.8275.x", DS_CMP_G8275    },
	{ NULL, 0 },
};

static struct config_enum delay_filter_enu[] = {
	{ "moving_average", FILTER_MOVING_AVERAGE },
	{ "moving_median",  FILTER_MOVING_MEDIAN  },
	{ NULL, 0 },
};

static struct config_enum delay_mech_enu[] = {
	{ "Auto", DM_AUTO },
	{ "COMMON_P2P", DM_COMMON_P2P },
	{ "E2E",  DM_E2E },
	{ "P2P",  DM_P2P },
	{ "NONE", DM_NO_MECHANISM },
	{ NULL, 0 },
};

static struct config_enum extts_polarity_enu[] = {
	{ "rising",  PTP_RISING_EDGE  },
	{ "falling", PTP_FALLING_EDGE },
	{ "both",    PTP_RISING_EDGE | PTP_FALLING_EDGE },
	{ NULL, 0 },
};

static struct config_enum hwts_filter_enu[] = {
	{ "normal",  HWTS_FILTER_NORMAL  },
	{ "check",   HWTS_FILTER_CHECK   },
	{ "full",    HWTS_FILTER_FULL    },
	{ NULL, 0 },
};

static struct config_enum ieee_c37_238_enu[] = {
	{ "none", IEEE_C37_238_VERSION_NONE },
	{ "2011", IEEE_C37_238_VERSION_2011 },
	{ "2017", IEEE_C37_238_VERSION_2017 },
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
	{ "onestep",  TS_ONESTEP   },
	{ "p2p1step", TS_P2P1STEP  },
	{ NULL, 0 },
};

static struct config_enum tsproc_enu[] = {
	{ "filter",        TSPROC_FILTER        },
	{ "raw",           TSPROC_RAW           },
	{ "filter_weight", TSPROC_FILTER_WEIGHT },
	{ "raw_weight",    TSPROC_RAW_WEIGHT    },
	{ NULL, 0 },
};

static struct config_enum as_capable_enu[] = {
	{ "true", AS_CAPABLE_TRUE },
	{ "auto", AS_CAPABLE_AUTO },
	{ NULL, 0 },
};

static struct config_enum bmca_enu[] = {
	{ "ptp",  BMCA_PTP  },
	{ "noop", BMCA_NOOP },
	{ NULL, 0 },
};

struct config_item config_tab[] = {
	PORT_ITEM_UIN("active_key_id", 0, 0, UINT32_MAX),
	PORT_ITEM_INT("allow_unauth", 0, 0, 2),
	PORT_ITEM_INT("allowedLostResponses", 3, 1, 255),
	PORT_ITEM_INT("announceReceiptTimeout", 3, 2, UINT8_MAX),
	PORT_ITEM_ENU("asCapable", AS_CAPABLE_AUTO, as_capable_enu),
	GLOB_ITEM_INT("assume_two_step", 0, 0, 1),
	PORT_ITEM_INT("boundary_clock_jbod", 0, 0, 1),
	PORT_ITEM_ENU("BMCA", BMCA_PTP, bmca_enu),
	GLOB_ITEM_INT("check_fup_sync", 0, 0, 1),
	GLOB_ITEM_INT("clientOnly", 0, 0, 1),
	GLOB_ITEM_INT("clockAccuracy", 0xfe, 0, UINT8_MAX),
	GLOB_ITEM_INT("clockClass", 248, 0, UINT8_MAX),
	GLOB_ITEM_STR("clockIdentity", "000000.0000.000000"),
	GLOB_ITEM_INT("clock_class_threshold", CLOCK_CLASS_THRESHOLD_DEFAULT, 6, CLOCK_CLASS_THRESHOLD_DEFAULT),
	GLOB_ITEM_ENU("clock_servo", CLOCK_SERVO_PI, clock_servo_enu),
	GLOB_ITEM_ENU("clock_type", CLOCK_TYPE_ORDINARY, clock_type_enu),
	PORT_ITEM_STR("cmlds.client_address", "/var/run/cmlds_client"),
	PORT_ITEM_INT("cmlds.domainNumber", 0, 0, 255),
	PORT_ITEM_INT("cmlds.majorSdoId", 2, 0, 0x0F),
	PORT_ITEM_INT("cmlds.port", 0, 0, UINT16_MAX),
	PORT_ITEM_STR("cmlds.server_address", "/var/run/cmlds_server"),
	GLOB_ITEM_ENU("dataset_comparison", DS_CMP_IEEE1588, dataset_comp_enu),
	PORT_ITEM_INT("delayAsymmetry", 0, INT_MIN, INT_MAX),
	PORT_ITEM_ENU("delay_filter", FILTER_MOVING_MEDIAN, delay_filter_enu),
	PORT_ITEM_INT("delay_filter_length", 10, 1, INT_MAX),
	PORT_ITEM_ENU("delay_mechanism", DM_E2E, delay_mech_enu),
	PORT_ITEM_INT("delay_response_timeout", 0, 0, UINT8_MAX),
	GLOB_ITEM_INT("dscp_event", 0, 0, 63),
	GLOB_ITEM_INT("dscp_general", 0, 0, 63),
	GLOB_ITEM_INT("domainNumber", 0, 0, 255),
	PORT_ITEM_INT("egressLatency", 0, INT_MIN, INT_MAX),
	PORT_ITEM_INT("fault_badpeernet_interval", 16, INT32_MIN, INT32_MAX),
	PORT_ITEM_INT("fault_reset_interval", 4, INT8_MIN, INT8_MAX),
	GLOB_ITEM_DBL("first_step_threshold", 0.00002, 0.0, DBL_MAX),
	PORT_ITEM_INT("follow_up_info", 0, 0, 1),
	GLOB_ITEM_INT("free_running", 0, 0, 1),
	PORT_ITEM_INT("freq_est_interval", 1, INT_MIN, INT_MAX),
	GLOB_ITEM_INT("G.8275.defaultDS.localPriority", 128, 1, UINT8_MAX),
	PORT_ITEM_INT("G.8275.portDS.localPriority", 128, 1, UINT8_MAX),
	GLOB_ITEM_INT("gmCapable", 1, 0, 1),
	GLOB_ITEM_ENU("hwts_filter", HWTS_FILTER_NORMAL, hwts_filter_enu),
	PORT_ITEM_INT("hybrid_e2e", 0, 0, 1),
	PORT_ITEM_INT("ignore_source_id", 0, 0, 1),
	PORT_ITEM_INT("ignore_transport_specific", 0, 0, 1),
	PORT_ITEM_INT("ingressLatency", 0, INT_MIN, INT_MAX),
	PORT_ITEM_INT("inhibit_announce", 0, 0, 1),
	PORT_ITEM_INT("inhibit_delay_req", 0, 0, 1),
	PORT_ITEM_INT("inhibit_multicast_service", 0, 0, 1),
	GLOB_ITEM_INT("initial_delay", 0, 0, INT_MAX),
	PORT_ITEM_INT("interface_rate_tlv", 0, 0, 1),
	GLOB_ITEM_INT("kernel_leap", 1, 0, 1),
	GLOB_ITEM_STR("leapfile", NULL),
	PORT_ITEM_INT("logAnnounceInterval", 1, INT8_MIN, INT8_MAX),
	PORT_ITEM_INT("logMinDelayReqInterval", 0, INT8_MIN, INT8_MAX),
	PORT_ITEM_INT("logMinPdelayReqInterval", 0, INT8_MIN, INT8_MAX),
	PORT_ITEM_INT("logSyncInterval", 0, INT8_MIN, INT8_MAX),
	GLOB_ITEM_INT("logging_level", LOG_INFO, PRINT_LEVEL_MIN, PRINT_LEVEL_MAX),
	PORT_ITEM_INT("masterOnly", 0, 0, 1), /*deprecated*/
	GLOB_ITEM_INT("maxStepsRemoved", 255, 2, UINT8_MAX),
	GLOB_ITEM_STR("message_tag", NULL),
	GLOB_ITEM_STR("manufacturerIdentity", "00:00:00"),
	GLOB_ITEM_INT("max_frequency", 900000000, 0, INT_MAX),
	PORT_ITEM_INT("min_neighbor_prop_delay", -20000000, INT_MIN, -1),
	PORT_ITEM_INT("msg_interval_request", 0, 0, 1),
	PORT_ITEM_INT("neighborPropDelayThresh", 20000000, 0, INT_MAX),
	PORT_ITEM_INT("net_sync_monitor", 0, 0, 1),
	PORT_ITEM_ENU("network_transport", TRANS_UDP_IPV4, nw_trans_enu),
	GLOB_ITEM_INT("ntpshm_segment", 0, INT_MIN, INT_MAX),
	GLOB_ITEM_INT("offsetScaledLogVariance", 0xffff, 0, UINT16_MAX),
	PORT_ITEM_INT("operLogPdelayReqInterval", 0, INT8_MIN, INT8_MAX),
	PORT_ITEM_INT("operLogSyncInterval", 0, INT8_MIN, INT8_MAX),
	PORT_ITEM_STR("p2p_dst_ipv4", "224.0.0.107"),
	PORT_ITEM_STR("p2p_dst_ipv6", "FF02:0:0:0:0:0:0:6B"),
	PORT_ITEM_STR("p2p_dst_mac", "01:80:C2:00:00:0E"),
	PORT_ITEM_INT("path_trace_enabled", 0, 0, 1),
	PORT_ITEM_INT("phc_index", -1, -1, INT_MAX),
	GLOB_ITEM_DBL("pi_integral_const", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_DBL("pi_integral_exponent", 0.4, -DBL_MAX, DBL_MAX),
	GLOB_ITEM_DBL("pi_integral_norm_max", 0.3, DBL_MIN, 2.0),
	GLOB_ITEM_DBL("pi_integral_scale", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_DBL("pi_proportional_const", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_DBL("pi_proportional_exponent", -0.3, -DBL_MAX, DBL_MAX),
	GLOB_ITEM_DBL("pi_proportional_norm_max", 0.7, DBL_MIN, 1.0),
	GLOB_ITEM_DBL("pi_proportional_scale", 0.0, 0.0, DBL_MAX),
	PORT_ITEM_ENU("power_profile.version", IEEE_C37_238_VERSION_NONE, ieee_c37_238_enu),
	PORT_ITEM_INT("power_profile.2011.grandmasterTimeInaccuracy", 0xFFFFFFFF, -1, INT_MAX),
	PORT_ITEM_INT("power_profile.2011.networkTimeInaccuracy", 0xFFFFFFFF, -1, INT_MAX),
	PORT_ITEM_INT("power_profile.2017.totalTimeInaccuracy", 0xFFFFFFFF, -1, INT_MAX),
	PORT_ITEM_INT("power_profile.grandmasterID", 0, 0, 0xFFFF),
	GLOB_ITEM_INT("priority1", 128, 0, UINT8_MAX),
	GLOB_ITEM_INT("priority2", 128, 0, UINT8_MAX),
	GLOB_ITEM_STR("productDescription", ";;"),
	PORT_ITEM_STR("ptp_dst_ipv4", "224.0.1.129"),
	PORT_ITEM_STR("ptp_dst_ipv6", "FF0E:0:0:0:0:0:0:181"),
	PORT_ITEM_STR("ptp_dst_mac", "01:1B:19:00:00:00"),
	GLOB_ITEM_INT("ptp_minor_version", 1, 0, 1),
	GLOB_ITEM_STR("refclock_sock_address", "/var/run/refclock.ptp.sock"),
	GLOB_ITEM_STR("revisionData", ";;"),
	GLOB_ITEM_STR("sa_file", NULL),
	GLOB_ITEM_INT("sanity_freq_limit", 200000000, 0, INT_MAX),
	PORT_ITEM_INT("serverOnly", 0, 0, 1),
	GLOB_ITEM_INT("servo_num_offset_values", 10, 0, INT_MAX),
	GLOB_ITEM_INT("servo_offset_threshold", 0, 0, INT_MAX),
	GLOB_ITEM_STR("slave_event_monitor", ""),
	GLOB_ITEM_INT("slaveOnly", 0, 0, 1), /*deprecated*/
	GLOB_ITEM_INT("socket_priority", 0, 0, 15),
	PORT_ITEM_INT("spp", -1, -1, UINT8_MAX),
	GLOB_ITEM_DBL("step_threshold", 0.0, 0.0, DBL_MAX),
	GLOB_ITEM_INT("step_window", 0, 0, INT_MAX),
	GLOB_ITEM_INT("summary_interval", 0, INT_MIN, INT_MAX),
	PORT_ITEM_INT("syncReceiptTimeout", 0, 0, UINT8_MAX),
	GLOB_ITEM_INT("tc_spanning_tree", 0, 0, 1),
	GLOB_ITEM_INT("timeSource", INTERNAL_OSCILLATOR, 0x10, 0xfe),
	GLOB_ITEM_ENU("time_stamping", TS_HARDWARE, timestamping_enu),
	PORT_ITEM_INT("transportSpecific", 0, 0, 0x0F),
	PORT_ITEM_INT("ts2phc.channel", 0, 0, INT_MAX),
	PORT_ITEM_INT("ts2phc.extts_correction", 0, INT_MIN, INT_MAX),
	PORT_ITEM_ENU("ts2phc.extts_polarity", PTP_RISING_EDGE, extts_polarity_enu),
	PORT_ITEM_INT("ts2phc.holdover", 0, 0, INT_MAX),
	PORT_ITEM_INT("ts2phc.master", 0, 0, 1),
	PORT_ITEM_INT("ts2phc.nmea_baudrate", 9600, 300, INT_MAX),
	PORT_ITEM_INT("ts2phc.nmea_delay", 0, INT_MIN, INT_MAX),
	GLOB_ITEM_STR("ts2phc.nmea_remote_host", ""),
	GLOB_ITEM_STR("ts2phc.nmea_remote_port", ""),
	GLOB_ITEM_STR("ts2phc.nmea_serialport", "/dev/ttyS0"),
	PORT_ITEM_INT("ts2phc.perout_phase", -1, 0, 999999999),
	PORT_ITEM_INT("ts2phc.pin_index", 0, 0, INT_MAX),
	GLOB_ITEM_INT("ts2phc.pulsewidth", 500000000, 1000000, 999000000),
	GLOB_ITEM_STR("ts2phc.tod_source", "generic"),
	PORT_ITEM_ENU("tsproc_mode", TSPROC_FILTER, tsproc_enu),
	GLOB_ITEM_INT("twoStepFlag", 1, 0, 1),
	GLOB_ITEM_INT("tx_timestamp_timeout", 10, 1, INT_MAX),
	PORT_ITEM_INT("udp_ttl", 1, 1, 255),
	PORT_ITEM_INT("udp6_scope", 0x0E, 0x00, 0x0F),
	GLOB_ITEM_STR("uds_address", "/var/run/ptp4l"),
	PORT_ITEM_INT("uds_file_mode", UDS_FILEMODE, 0, 0777),
	GLOB_ITEM_STR("uds_ro_address", "/var/run/ptp4lro"),
	PORT_ITEM_INT("uds_ro_file_mode", UDS_RO_FILEMODE, 0, 0777),
	PORT_ITEM_INT("unicast_listen", 0, 0, 1),
	PORT_ITEM_INT("unicast_master_table", 0, 0, INT_MAX),
	PORT_ITEM_INT("unicast_req_duration", 3600, 10, INT_MAX),
	GLOB_ITEM_INT("use_syslog", 1, 0, 1),
	GLOB_ITEM_STR("userDescription", ""),
	GLOB_ITEM_INT("utc_offset", CURRENT_UTC_OFFSET, 0, INT_MAX),
	GLOB_ITEM_INT("verbose", 0, 0, 1),
	GLOB_ITEM_INT("write_phase_mode", 0, 0, 1),
};

static struct unicast_master_table *current_uc_mtab;

static enum parser_result
parse_fault_interval(struct config *cfg, const char *section,
		     const char *option, const char *value);

static struct config_item *config_section_item(struct config *cfg,
					       const char *section,
					       const char *name)
{
	char buf[CONFIG_LABEL_SIZE + MAX_IFNAME_SIZE];

	if (snprintf(buf, sizeof(buf), "%s.%s", section, name) >= sizeof(buf))
		return NULL;
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

static int config_switch_unicast_mtab(struct config *cfg, int idx, int line_num)
{
	struct unicast_master_table *table;

	if (idx < 1) {
		fprintf(stderr, "line %d: table_id %d is out of range. "
			"Must be in the range %d to %d\n",
			line_num, idx, 1, INT_MAX);
		return -1;
	}
	STAILQ_FOREACH(table, &cfg->unicast_master_tables, list) {
		if (table->table_index == idx) {
			fprintf(stderr, "line %d: table_id %d already taken\n",
				line_num, idx);
			return -1;
		}
	}
	table = calloc(1, sizeof(*table));
	if (!table) {
		fprintf(stderr, "low memory\n");
		return -1;
	}
	STAILQ_INIT(&table->addrs);
	table->table_index = idx;
	memset(&table->peer_addr.portIdentity, 0xff,
	       sizeof(table->peer_addr.portIdentity));
	STAILQ_INSERT_TAIL(&cfg->unicast_master_tables, table, list);
	current_uc_mtab = table;
	return 0;
}

static int config_unicast_mtab_address(enum transport_type type, char *address,
				       int line_num)
{
	struct unicast_master_address *item;

	if (!current_uc_mtab) {
		fprintf(stderr, "line %d: missing table_id\n", line_num);
		return -1;
	}
	item = calloc(1, sizeof(*item));
	if (!item) {
		fprintf(stderr, "low memory\n");
		return -1;
	}
	if (str2addr(type, address, &item->address)) {
		fprintf(stderr, "line %d: bad address\n", line_num);
		free(item);
		return -1;
	}
	memset(&item->portIdentity, 0xff, sizeof(item->portIdentity));
	item->type = type;
	STAILQ_INSERT_TAIL(&current_uc_mtab->addrs, item, list);
	current_uc_mtab->count++;

	return 0;
}

static int config_unicast_mtab_peer(char *address, int line_num)
{
	if (!current_uc_mtab) {
		fprintf(stderr, "line %d: missing table_id\n", line_num);
		return -1;
	}
	if (current_uc_mtab->peer_name) {
		free(current_uc_mtab->peer_name);
	}
	current_uc_mtab->peer_name = strdup(address);
	if (!current_uc_mtab->peer_name) {
		fprintf(stderr, "low memory\n");
		return -1;
	}
	return 0;
}

static int config_unicast_mtab_query_interval(int lqi, int line_num)
{
	if (!current_uc_mtab) {
		fprintf(stderr, "line %d: missing table_id\n", line_num);
		return -1;
	}
	if (lqi < INT8_MIN || lqi > INT8_MAX) {
		fprintf(stderr, "line %d: logQueryInterval %d out of range\n",
			line_num, lqi);
		return -1;
	}
	current_uc_mtab->logQueryInterval = lqi;
	return 0;
}

static enum parser_result parse_section_line(char *s, enum config_section *section)
{
	if (!strcasecmp(s, "[global]")) {
		*section = GLOBAL_SECTION;
	} else if (!strcasecmp(s, "[unicast_master_table]")) {
		*section = UC_MTAB_SECTION;
		current_uc_mtab = NULL;
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
				     int commandline,
				     const char *section,
				     const char *option,
				     const char *value)
{
	enum parser_result r;
	struct config_item *cgi, *dst;
	struct config_enum *cte;
	double df;
	int val;
	uint32_t uval;

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
	case CFG_TYPE_UINT:
		r = get_ranged_uint(value, &uval, cgi->min.u, cgi->max.u);
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
	} else if (!commandline && cgi->flags & CFG_ITEM_LOCKED) {
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
	case CFG_TYPE_UINT:
		dst->val.u = uval;
		break;
	}

	if (commandline) {
		dst->flags |= CFG_ITEM_LOCKED;
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

static int parse_unicast_mtab_line(struct config *cfg, char *line, int line_num)
{
	char address[64 + 1] = {0}, transport[16 + 1] = {0};
	enum transport_type type = TRANS_UDS;
	struct config_enum *cte;
	int cnt, lqi, table_id;

	cnt = sscanf(line, " table_id %d", &table_id);
	if (cnt == 1) {
		return config_switch_unicast_mtab(cfg, table_id, line_num);
	}
	cnt = sscanf(line, " logQueryInterval %d", &lqi);
	if (cnt == 1) {
		return config_unicast_mtab_query_interval(lqi, line_num);
	}
	cnt = sscanf(line, " peer_address %64s", address);
	if (cnt == 1) {
		return config_unicast_mtab_peer(address, line_num);
	}
	cnt = sscanf(line, " %16s %64s", transport, address);
	if (cnt != 2) {
		fprintf(stderr, "bad master table at line %d\n", line_num);
		return -1;
	}
	for (cte = nw_trans_enu; cte->label; cte++) {
		if (!strcasecmp(cte->label, transport)) {
			type = cte->value;
			break;
		}
	}
	return config_unicast_mtab_address(type, address, line_num);
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
	} else if (!strcmp(*option, "masterOnly")) {
		new_option = "serverOnly";
	} else if (!strcmp(*option, "slaveOnly")) {
		new_option = "clientOnly";
	}

	if (new_option) {
		fprintf(stderr, "option %s is deprecated, please use %s instead\n",
				*option, new_option);
		*option = new_option;
	}
}

static struct option *config_alloc_longopts(void)
{
	struct config_item *ci;
	struct option *opts;
	int i;

	opts = calloc(1, (1 + N_CONFIG_ITEMS) * sizeof(*opts));
	if (!opts) {
		return NULL;
	}
	for (i = 0; i < N_CONFIG_ITEMS; i++) {
		ci = &config_tab[i];
		opts[i].name = ci->label;
		opts[i].has_arg = required_argument;
		/* Avoid bug in detection of ambiguous options in glibc */
		opts[i].flag = &opts[i].val;
	}

	return opts;
}

int config_read(const char *name, struct config *cfg)
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
				char port[129];
				if (1 != sscanf(line, " %128s", port)) {
					fprintf(stderr, "could not parse port name on line %d\n",
							line_num);
					goto parse_error;
				}
				current_port = config_create_interface(port, cfg);
				if (!current_port)
					goto parse_error;
			}
			continue;
		}

		if (current_section == UC_MTAB_SECTION) {
			if (parse_unicast_mtab_line(cfg, line, line_num)) {
				goto parse_error;
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
				"global" : interface_name(current_port));
			goto parse_error;
		}

		check_deprecated_options(&option);

		parser_res = parse_item(cfg, 0, current_section == GLOBAL_SECTION ?
					NULL : interface_name(current_port),
					option, value);
		switch (parser_res) {
		case PARSED_OK:
			break;
		case NOT_PARSED:
			fprintf(stderr, "unknown option %s at line %d in %s section\n",
				option, line_num,
				current_section == GLOBAL_SECTION ? "global" :
				interface_name(current_port));
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

struct interface *config_create_interface(const char *name, struct config *cfg)
{
	struct interface *iface;
	const char *ifname;

	/* only create each interface once (by name) */
	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		ifname = interface_name(iface);
		if (0 == strncmp(name, ifname, MAX_IFNAME_SIZE))
			return iface;
	}

	iface = interface_create(name, NULL);
	if (!iface) {
		fprintf(stderr, "cannot allocate memory for a port\n");
		return NULL;
	}
	STAILQ_INSERT_TAIL(&cfg->interfaces, iface, list);
	cfg->n_interfaces++;

	return iface;
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
	STAILQ_INIT(&cfg->unicast_master_tables);
	STAILQ_INIT(&cfg->security_association_database);

	cfg->opts = config_alloc_longopts();
	if (!cfg->opts) {
		free(cfg);
		return NULL;
	}

	cfg->htab = hash_create();
	if (!cfg->htab) {
		free(cfg->opts);
		free(cfg);
		return NULL;
	}

	/* Populate the hash table with global defaults. */
	for (i = 0; i < N_CONFIG_ITEMS; i++) {
		ci = &config_tab[i];
		ci->flags |= CFG_ITEM_STATIC;
		if (snprintf(buf, sizeof(buf), "global.%s", ci->label) >=
		    sizeof(buf)) {
			fprintf(stderr, "option %s too long\n", ci->label);
			goto fail;
		}
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
	free(cfg->opts);
	free(cfg);
	return NULL;
}

void config_destroy(struct config *cfg)
{
	struct unicast_master_address *address;
	struct unicast_master_table *table;
	struct interface *iface;

	while ((iface = STAILQ_FIRST(&cfg->interfaces))) {
		STAILQ_REMOVE_HEAD(&cfg->interfaces, list);
		interface_destroy(iface);
	}
	while ((table = STAILQ_FIRST(&cfg->unicast_master_tables))) {
		while ((address = STAILQ_FIRST(&table->addrs))) {
			STAILQ_REMOVE_HEAD(&table->addrs, list);
			free(address);
		}
		if (table->peer_name) {
			free(table->peer_name);
		}
		STAILQ_REMOVE_HEAD(&cfg->unicast_master_tables, list);
		free(table);
	}
	hash_destroy(cfg->htab, config_item_free);
	free(cfg->opts);
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
	case CFG_TYPE_UINT:
		pr_err("bug: config option %s type mismatch!", option);
		exit(-1);
	case CFG_TYPE_INT:
	case CFG_TYPE_ENUM:
		break;
	}
	pr_debug("config item %s.%s is %d", section, option, ci->val.i);
	return ci->val.i;
}

uint32_t config_get_uint(struct config *cfg, const char *section,
			 const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci || ci->type != CFG_TYPE_UINT) {
		pr_err("bug: config option %s missing or invalid!", option);
		exit(-1);
	}
	pr_debug("config item %s.%s is %u", section, option, ci->val.u);
	return ci->val.u;
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

int config_harmonize_onestep(struct config *cfg)
{
	enum timestamp_type tstype = config_get_int(cfg, NULL, "time_stamping");
	int two_step_flag = config_get_int(cfg, NULL, "twoStepFlag");

	switch (tstype) {
	case TS_SOFTWARE:
	case TS_LEGACY_HW:
		if (!two_step_flag) {
			pr_err("one step is only possible "
			       "with hardware time stamping");
			return -1;
		}
		break;
	case TS_HARDWARE:
		if (!two_step_flag) {
			pr_debug("upgrading to one step time stamping "
				 "in order to match the twoStepFlag");
			if (config_set_int(cfg, "time_stamping", TS_ONESTEP)) {
				return -1;
			}
		}
		break;
	case TS_ONESTEP:
	case TS_P2P1STEP:
		if (two_step_flag) {
			pr_debug("one step mode implies twoStepFlag=0, "
				 "clearing twoStepFlag to match");
			if (config_set_int(cfg, "twoStepFlag", 0)) {
				return -1;
			}
		}
		break;
	}

	return 0;
}

int config_parse_option(struct config *cfg, const char *opt, const char *val)
{
	enum parser_result result;

	check_deprecated_options(&opt);

	result = parse_item(cfg, 1, NULL, opt, val);

	switch (result) {
	case PARSED_OK:
		return 0;
	case NOT_PARSED:
		fprintf(stderr, "unknown option %s\n", opt);
		break;
	case BAD_VALUE:
		fprintf(stderr, "%s is a bad value for option %s\n", val, opt);
		break;
	case MALFORMED:
		fprintf(stderr, "%s is a malformed value for option %s\n",
			val, opt);
		break;
	case OUT_OF_RANGE:
		fprintf(stderr, "%s is an out of range value for option %s\n",
			val, opt);
		break;
	}
	return -1;
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
	case CFG_TYPE_UINT:
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

int config_set_uint(struct config *cfg, const char *option, uint32_t val)
{
	struct config_item *ci = config_find_item(cfg, NULL, option);

	if (!ci || ci->type != CFG_TYPE_UINT) {
		pr_err("bug: config option %s missing or invalid!", option);
		return -1;
	}
	ci->flags |= CFG_ITEM_LOCKED;
	ci->val.u = val;
	pr_debug("locked item global.%s as %u", option, ci->val.u);
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
