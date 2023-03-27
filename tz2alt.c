/**
 * @file tz2alt.c
 * @note Copyright (C) 2021 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "lstab.h"
#include "pmc_common.h"
#include "print.h"
#include "version.h"
#include "tz.h"

#define DEFAULT_TZ	"PST8PDT"
#define DEFAULT_PERIOD	3600
#define DEFAULT_WINDOW	(3600 * 24 * 30 * 3)

static int key_field, period = DEFAULT_PERIOD, window = DEFAULT_WINDOW;
static char uds_local[MAX_IFNAME_SIZE + 1];
static struct lstab *lstab;
static struct config *cfg;

struct tzinfo {
	const char		*name;
	char			display_name[MAX_TZ_DISPLAY_NAME + 1];
	time_t			timestamp;

	/* Following fields populated by get_offsets. */

	time_t			local_utc_offset;
	time_t			local_tai_offset;
	int			tai_utc_offset;
	enum lstab_result	tai_result;
};

static int get_offsets(struct tzinfo *tz);

static bool offsets_equal(struct tzinfo *a, struct tzinfo *b)
{
	return a->local_utc_offset == b->local_utc_offset;
}

static bool find_next_discontinuity(struct tzinfo *tz, struct tzinfo *next)
{
	time_t i, j, n;
	bool gt;

	next->timestamp = tz->timestamp + window;
	get_offsets(next);
	if (offsets_equal(tz, next)) {
		return false;
	}

	i = 0;
	j = window;

	while (1) {
		next->timestamp = tz->timestamp + i;
		get_offsets(next);
		gt = offsets_equal(tz, next);
		if (gt) {
			n = j - i - 1;
		} else {
			j = i;
			i = 0;
			n = j - i - 1;
		}
		if (!n) {
			if (gt) {
				next->timestamp++;
				get_offsets(next);
			}
			break;
		}
		i += (n + 1) / 2;
	}

	return true;
}

static int get_offsets(struct tzinfo *tz)
{
	struct tm tm = {0};
	time_t t2;

	tz->tai_result = lstab_utc2tai(lstab, tz->timestamp,
				       &tz->tai_utc_offset);
	if (tz->tai_result == LSTAB_UNKNOWN) {
		pr_err("leap second table is stale");
		return -1;
	}

	setenv("TZ", tz->name, 1);
	tzset();
	if (!localtime_r(&tz->timestamp, &tm)) {
		return -1;
	}

	setenv("TZ", "UTC", 1);
	tzset();
	t2 = mktime(&tm);
	tz->local_utc_offset = t2 - tz->timestamp;
	tz->local_tai_offset = tz->local_utc_offset - tz->tai_utc_offset;

	return 0;
}

static int get_unambiguous_time(struct tzinfo *tz)
{
	int err;

	do {
		tz->timestamp = time(NULL);
		err = get_offsets(tz);
	} while (tz->tai_result == LSTAB_AMBIGUOUS);

	return err;
}

static void show_timezone_info(const char *label, struct tzinfo *tz)
{
	pr_debug("%s %s ts %ld local-utc %ld tai-utc %d local-tai %ld %s",
		 label,
		 tz->name,
		 tz->timestamp,
		 tz->local_utc_offset,
		 tz->tai_utc_offset,
		 tz->local_tai_offset,
		 tz->tai_result == LSTAB_OK ? "valid" : "invalid");
}

/* Returns true if display name was truncated. */
static bool tz_set_name(struct tzinfo *tz, const char *name)
{
	const char *suffix;
	int len;

	memset(tz->display_name, 0, sizeof(tz->display_name));
	tz->name = name;

	len = strlen(name);
	if (len <= MAX_TZ_DISPLAY_NAME) {
		strncpy(tz->display_name, name, sizeof(tz->display_name) - 1);
		return false;
	}

	/*
	 * The displayName field is limited to 10 characters, but
	 * there are many valid time zone names like "Europe/Vienna".
	 * Use the suffix if present.
	 */
	suffix = strchr(name, '/');
	if (suffix) {
		suffix++;
		len = strlen(suffix);
		if (len > 0 && len <= MAX_TZ_DISPLAY_NAME) {
			strncpy(tz->display_name, suffix,
				sizeof(tz->display_name) - 1);
			return true;
		}
	}

	/* No nice suffix to be found, so just truncate. */
	strncpy(tz->display_name, name, sizeof(tz->display_name) - 1);

	return true;
}

static int update_ptp_serivce(struct tzinfo *tz, struct tzinfo *next)
{
	struct alternate_time_offset_properties atop;
	struct management_tlv_datum mtd;
	uint64_t time_of_next_jump;
	struct pmc *pmc;
	int err;

	pmc = pmc_create(cfg, TRANS_UDS, uds_local, 0,
			 config_get_int(cfg, NULL, "domainNumber"),
			 config_get_int(cfg, NULL, "transportSpecific") << 4, 1);
	if (!pmc) {
		return -1;
	}
	err = pmc_send_set_aton(pmc, MID_ALTERNATE_TIME_OFFSET_NAME,
				key_field, tz->display_name);
	if (err) {
		return err;
	}
	memset(&atop, 0, sizeof(atop));
	atop.keyField = key_field;
	atop.currentOffset = tz->local_tai_offset;
	if (next) {
		atop.jumpSeconds = next->local_tai_offset - tz->local_tai_offset;
		time_of_next_jump = (uint64_t) next->timestamp;
		atop.timeOfNextJump.seconds_lsb = time_of_next_jump & 0xffffffff;
		atop.timeOfNextJump.seconds_msb = time_of_next_jump >> 32;
	}
	err = pmc_send_set_action(pmc, MID_ALTERNATE_TIME_OFFSET_PROPERTIES,
				  &atop, sizeof(atop));
	if (err) {
		return err;
	}
	mtd.val = key_field;
	mtd.reserved = 1; /*enable field*/
	err = pmc_send_set_action(pmc, MID_ALTERNATE_TIME_OFFSET_ENABLE,
				  &mtd, sizeof(mtd));
	if (err) {
		return err;
	}

	pmc_destroy(pmc);
	return 0;
}

static int do_tztool(const char *timezone)
{
	struct tzinfo nx, tz;
	const char *leapfile;
	bool pending;
	char buf[64];
	int err;

	if (key_field > MAX_TIME_ZONES - 1) {
		pr_err("key field %d exceeds maximum of %d", key_field,
		       MAX_TIME_ZONES - 1);
		return -1;
	}

	tz_set_name(&nx, timezone);
	if (tz_set_name(&tz, timezone)) {
		pr_info("truncating time zone display name from %s to %s",
			tz.name, tz.display_name);
	}

	leapfile = config_get_string(cfg, NULL, "leapfile");
	if (!leapfile) {
		pr_err("please specify leap second table with --leapfile");
		return -1;
	}

	while (is_running()) {

		/* Read the leap seconds file again as it may have changed. */
		lstab = lstab_create(leapfile);
		if (!lstab) {
			pr_err("failed to create leap second table");
			return -1;
		}

		err = get_unambiguous_time(&tz);
		if (err) {
			return err;
		}
		show_timezone_info("current time  = ", &tz);

		pending = find_next_discontinuity(&tz, &nx);
		if (pending) {
			setenv("TZ", nx.name, 1);
			tzset();
			if (ctime_r(&nx.timestamp, buf)) {
				buf[strlen(buf) - 1] = 0;
			}
			show_timezone_info("discontinuity = ", &nx);
			pr_info("next discontinuity %s %s", buf, nx.name);
		} else {
			pr_info("no discontinuity within %d second window", window);
		}

		lstab_destroy(lstab);
		lstab = NULL;

		err = update_ptp_serivce(&tz, pending ? &nx : NULL);
		if (err) {
			pr_err("failed to update PTP service");
			return err;
		}
		sleep(period);
	}
	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" -f [file] read configuration from 'file'\n"
		" -h        prints this message and exits\n"
		" -k [num]  key field for the ALTERNATE_TIME_OFFSET_INDICATOR TLV\n"
		" -p [num]  period between updates in seconds, default %d\n"
		" -v        prints the software version and exits\n"
		" -w [num]  look ahead time window in seconds, default %d\n"
		" -z zone   Time zone string, default '%s'\n"
		"           See /usr/share/zoneinfo for valid strings\n"
		"\n",
		progname, DEFAULT_PERIOD, DEFAULT_WINDOW, DEFAULT_TZ);
}

int main(int argc, char *argv[])
{
	char *config = NULL, *progname, *timezone = DEFAULT_TZ;
	int c, err = 0, index;
	struct option *opts;

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
	while (EOF != (c = getopt_long(argc, argv, "f:hk:p:vw:z:", opts, &index))) {
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
		case 'k':
			key_field = atoi(optarg);
			break;
		case 'p':
			period = atoi(optarg);
			break;
		case 'v':
			version_show(stdout);
			config_destroy(cfg);
			return 0;
		case 'w':
			window = atoi(optarg);
			break;
		case 'z':
			timezone = optarg;
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

	print_set_syslog(0);
	print_set_verbose(1);

	if (config && (err = config_read(config, cfg))) {
		goto out;
	}

	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));
	snprintf(uds_local, sizeof(uds_local), "/var/run/tztool.%d", getpid());

	err = do_tztool(timezone);
out:
	config_destroy(cfg);
	return err;
}
