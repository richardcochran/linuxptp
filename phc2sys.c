/**
 * @file phc2sys.c
 * @brief Utility program to synchronize two clocks via a PPS.
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
#include <fcntl.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/pps.h>
#include <linux/ptp_clock.h>

#include "clockadj.h"
#include "clockcheck.h"
#include "ds.h"
#include "fsm.h"
#include "missing.h"
#include "phc.h"
#include "pi.h"
#include "pmc_common.h"
#include "print.h"
#include "servo.h"
#include "sk.h"
#include "stats.h"
#include "sysoff.h"
#include "tlv.h"
#include "util.h"
#include "version.h"

#define KP 0.7
#define KI 0.3
#define NS_PER_SEC 1000000000LL

#define PHC_PPS_OFFSET_LIMIT 10000000
#define PMC_UPDATE_INTERVAL (60 * NS_PER_SEC)

struct clock;
static int update_sync_offset(struct clock *clock, int64_t offset, uint64_t ts);

static clockid_t clock_open(char *device)
{
	struct sk_ts_info ts_info;
	char phc_device[16];
	int clkid;

	/* check if device is CLOCK_REALTIME */
	if (!strcasecmp(device, "CLOCK_REALTIME"))
		return CLOCK_REALTIME;

	/* check if device is valid phc device */
	clkid = phc_open(device);
	if (clkid != CLOCK_INVALID)
		return clkid;

	/* check if device is a valid ethernet device */
	if (sk_get_ts_info(device, &ts_info) || !ts_info.valid) {
		fprintf(stderr, "unknown clock %s: %m\n", device);
		return CLOCK_INVALID;
	}

	if (ts_info.phc_index < 0) {
		fprintf(stderr, "interface %s does not have a PHC\n", device);
		return CLOCK_INVALID;
	}

	sprintf(phc_device, "/dev/ptp%d", ts_info.phc_index);
	clkid = phc_open(phc_device);
	if (clkid == CLOCK_INVALID)
		fprintf(stderr, "cannot open %s: %m\n", device);
	return clkid;
}

static int read_phc(clockid_t clkid, clockid_t sysclk, int readings,
		    int64_t *offset, uint64_t *ts, int64_t *delay)
{
	struct timespec tdst1, tdst2, tsrc;
	int i;
	int64_t interval, best_interval = INT64_MAX;

	/* Pick the quickest clkid reading. */
	for (i = 0; i < readings; i++) {
		if (clock_gettime(sysclk, &tdst1) ||
				clock_gettime(clkid, &tsrc) ||
				clock_gettime(sysclk, &tdst2)) {
			pr_err("failed to read clock: %m");
			return 0;
		}

		interval = (tdst2.tv_sec - tdst1.tv_sec) * NS_PER_SEC +
			tdst2.tv_nsec - tdst1.tv_nsec;

		if (best_interval > interval) {
			best_interval = interval;
			*offset = (tdst1.tv_sec - tsrc.tv_sec) * NS_PER_SEC +
				tdst1.tv_nsec - tsrc.tv_nsec + interval / 2;
			*ts = tdst2.tv_sec * NS_PER_SEC + tdst2.tv_nsec;
		}
	}
	*delay = best_interval;

	return 1;
}

struct clock {
	clockid_t clkid;
	struct servo *servo;
	enum servo_state servo_state;
	const char *source_label;
	struct stats *offset_stats;
	struct stats *freq_stats;
	struct stats *delay_stats;
	unsigned int stats_max_count;
	int sync_offset;
	int sync_offset_direction;
	int leap;
	int leap_set;
	int kernel_leap;
	struct pmc *pmc;
	int pmc_ds_idx;
	int pmc_ds_requested;
	uint64_t pmc_last_update;
	struct clockcheck *sanity_check;
};

static void update_clock_stats(struct clock *clock,
			       int64_t offset, double freq, int64_t delay)
{
	struct stats_result offset_stats, freq_stats, delay_stats;

	stats_add_value(clock->offset_stats, offset);
	stats_add_value(clock->freq_stats, freq);
	if (delay >= 0)
		stats_add_value(clock->delay_stats, delay);

	if (stats_get_num_values(clock->offset_stats) < clock->stats_max_count)
		return;

	stats_get_result(clock->offset_stats, &offset_stats);
	stats_get_result(clock->freq_stats, &freq_stats);

	if (!stats_get_result(clock->delay_stats, &delay_stats)) {
		pr_info("rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f "
			"delay %5.0f +/- %3.0f",
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev,
			delay_stats.mean, delay_stats.stddev);
	} else {
		pr_info("rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f",
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev);
	}

	stats_reset(clock->offset_stats);
	stats_reset(clock->freq_stats);
	stats_reset(clock->delay_stats);
}

static void update_clock(struct clock *clock,
			 int64_t offset, uint64_t ts, int64_t delay)
{
	enum servo_state state;
	double ppb;

	if (update_sync_offset(clock, offset, ts))
		return;

	if (clock->sync_offset_direction)
		offset += clock->sync_offset * NS_PER_SEC *
			clock->sync_offset_direction;

	if (clock->sanity_check && clockcheck_sample(clock->sanity_check, ts))
		servo_reset(clock->servo);

	ppb = servo_sample(clock->servo, offset, ts, &state);
	clock->servo_state = state;

	switch (state) {
	case SERVO_UNLOCKED:
		break;
	case SERVO_JUMP:
		clockadj_step(clock->clkid, -offset);
		if (clock->sanity_check)
			clockcheck_step(clock->sanity_check, -offset);
		/* Fall through. */
	case SERVO_LOCKED:
		clockadj_set_freq(clock->clkid, -ppb);
		if (clock->clkid == CLOCK_REALTIME)
			sysclk_set_sync();
		if (clock->sanity_check)
			clockcheck_set_freq(clock->sanity_check, -ppb);
		break;
	}

	if (clock->offset_stats) {
		update_clock_stats(clock, offset, ppb, delay);
	} else {
		if (delay >= 0) {
			pr_info("%s offset %9" PRId64 " s%d freq %+7.0f "
				"delay %6" PRId64,
				clock->source_label, offset, state, ppb, delay);
		} else {
			pr_info("%s offset %9" PRId64 " s%d freq %+7.0f",
				clock->source_label, offset, state, ppb);
		}
	}
}

static void enable_pps_output(clockid_t src)
{
	int enable = 1;

	if (!phc_has_pps(src))
		return;
	if (ioctl(CLOCKID_TO_FD(src), PTP_ENABLE_PPS, enable) < 0)
		pr_warning("failed to enable PPS output");
}

static int read_pps(int fd, int64_t *offset, uint64_t *ts)
{
	struct pps_fdata pfd;

	pfd.timeout.sec = 10;
	pfd.timeout.nsec = 0;
	pfd.timeout.flags = ~PPS_TIME_INVALID;
	if (ioctl(fd, PPS_FETCH, &pfd)) {
		pr_err("failed to fetch PPS: %m");
		return 0;
	}

	*ts = pfd.info.assert_tu.sec * NS_PER_SEC;
	*ts += pfd.info.assert_tu.nsec;

	*offset = *ts % NS_PER_SEC;
	if (*offset > NS_PER_SEC / 2)
		*offset -= NS_PER_SEC;

	return 1;
}

static int do_pps_loop(struct clock *clock, int fd,
		       clockid_t src, int n_readings)
{
	int64_t pps_offset, phc_offset, phc_delay;
	uint64_t pps_ts, phc_ts;

	clock->source_label = "pps";

	if (src == CLOCK_INVALID) {
		/* The sync offset can't be applied with PPS alone. */
		clock->sync_offset_direction = 0;
	} else {
		enable_pps_output(src);
	}

	while (1) {
		if (!read_pps(fd, &pps_offset, &pps_ts)) {
			continue;
		}

		/* If a PHC is available, use it to get the whole number
		   of seconds in the offset and PPS for the rest. */
		if (src != CLOCK_INVALID) {
			if (!read_phc(src, clock->clkid, n_readings,
				      &phc_offset, &phc_ts, &phc_delay))
				return -1;

			/* Convert the time stamp to the PHC time. */
			phc_ts -= phc_offset;

			/* Check if it is close to the start of the second. */
			if (phc_ts % NS_PER_SEC > PHC_PPS_OFFSET_LIMIT) {
				pr_warning("PPS is not in sync with PHC"
					   " (0.%09lld)", phc_ts % NS_PER_SEC);
				continue;
			}

			phc_ts = phc_ts / NS_PER_SEC * NS_PER_SEC;
			pps_offset = pps_ts - phc_ts;
		}

		update_clock(clock, pps_offset, pps_ts, -1);
	}
	close(fd);
	return 0;
}

static int do_sysoff_loop(struct clock *clock, clockid_t src,
			  struct timespec *interval, int n_readings)
{
	uint64_t ts;
	int64_t offset, delay;
	int err = 0, fd = CLOCKID_TO_FD(src);

	clock->source_label = "sys";

	while (1) {
		clock_nanosleep(CLOCK_MONOTONIC, 0, interval, NULL);
		if (sysoff_measure(fd, n_readings, &offset, &ts, &delay)) {
			err = -1;
			break;
		}
		update_clock(clock, offset, ts, delay);
	}
	return err;
}

static int do_phc_loop(struct clock *clock, clockid_t src,
		       struct timespec *interval, int n_readings)
{
	uint64_t ts;
	int64_t offset, delay;

	clock->source_label = "phc";

	while (1) {
		clock_nanosleep(CLOCK_MONOTONIC, 0, interval, NULL);
		if (!read_phc(src, clock->clkid, n_readings,
			      &offset, &ts, &delay)) {
			continue;
		}
		update_clock(clock, offset, ts, delay);
	}
	return 0;
}

static int is_msg_mgt(struct ptp_message *msg)
{
	struct TLV *tlv;

	if (msg_type(msg) != MANAGEMENT)
		return 0;
	if (management_action(msg) != RESPONSE)
		return 0;
	if (msg->tlv_count != 1)
		return 0;
	tlv = (struct TLV *) msg->management.suffix;
	if (tlv->type != TLV_MANAGEMENT)
		return 0;
	return 1;
}

static int get_mgt_id(struct ptp_message *msg)
{
	struct management_tlv *mgt = (struct management_tlv *) msg->management.suffix;
	return mgt->id;
}

static void *get_mgt_data(struct ptp_message *msg)
{
	struct management_tlv *mgt = (struct management_tlv *) msg->management.suffix;
	return mgt->data;
}

static int init_pmc(struct clock *clock, int domain_number)
{
	clock->pmc = pmc_create(TRANS_UDS, "/var/run/phc2sys", 0,
				domain_number, 0, 1);
	if (!clock->pmc) {
		pr_err("failed to create pmc");
		return -1;
	}

	return 0;
}

static int run_pmc(struct clock *clock, int timeout,
		   int wait_sync, int get_utc_offset)
{
	struct ptp_message *msg;
	struct timePropertiesDS *tds;
	void *data;
#define N_FD 1
	struct pollfd pollfd[N_FD];
	int cnt, ds_done;
#define N_ID 2
	int ds_ids[N_ID] = {
		PORT_DATA_SET,
		TIME_PROPERTIES_DATA_SET
	};

	while (clock->pmc_ds_idx < N_ID) {
		/* Check if the data set is really needed. */
		if ((ds_ids[clock->pmc_ds_idx] == PORT_DATA_SET &&
		     !wait_sync) ||
		    (ds_ids[clock->pmc_ds_idx] == TIME_PROPERTIES_DATA_SET &&
		     !get_utc_offset)) {
			clock->pmc_ds_idx++;
			continue;
		}

		pollfd[0].fd = pmc_get_transport_fd(clock->pmc);
		pollfd[0].events = POLLIN|POLLPRI;
		if (!clock->pmc_ds_requested)
			pollfd[0].events |= POLLOUT;

		cnt = poll(pollfd, N_FD, timeout);
		if (cnt < 0) {
			pr_err("poll failed");
			return -1;
		}
		if (!cnt) {
			/* Request the data set again in the next run. */
			clock->pmc_ds_requested = 0;
			return 0;
		}

		/* Send a new request if there are no pending messages. */
		if ((pollfd[0].revents & POLLOUT) &&
		    !(pollfd[0].revents & (POLLIN|POLLPRI))) {
			pmc_send_get_action(clock->pmc,
					    ds_ids[clock->pmc_ds_idx]);
			clock->pmc_ds_requested = 1;
		}

		if (!(pollfd[0].revents & (POLLIN|POLLPRI)))
			continue;

		msg = pmc_recv(clock->pmc);

		if (!msg)
			continue;

		if (!is_msg_mgt(msg) ||
		    get_mgt_id(msg) != ds_ids[clock->pmc_ds_idx]) {
			msg_put(msg);
			continue;
		}

		data = get_mgt_data(msg);
		ds_done = 0;

		switch (get_mgt_id(msg)) {
		case PORT_DATA_SET:
			switch (((struct portDS *)data)->portState) {
			case PS_MASTER:
			case PS_SLAVE:
				ds_done = 1;
				break;
			}

			break;
		case TIME_PROPERTIES_DATA_SET:
			tds = (struct timePropertiesDS *)data;
			if (tds->flags & PTP_TIMESCALE) {
				clock->sync_offset = tds->currentUtcOffset;
				if (tds->flags & LEAP_61)
					clock->leap = 1;
				else if (tds->flags & LEAP_59)
					clock->leap = -1;
				else
					clock->leap = 0;
			}
			ds_done = 1;
			break;
		}

		if (ds_done) {
			/* Proceed with the next data set. */
			clock->pmc_ds_idx++;
			clock->pmc_ds_requested = 0;
		}
		msg_put(msg);
	}

	clock->pmc_ds_idx = 0;
	return 1;
}

static void close_pmc(struct clock *clock)
{
	pmc_destroy(clock->pmc);
	clock->pmc = NULL;
}

static int update_sync_offset(struct clock *clock, int64_t offset, uint64_t ts)
{
	int clock_leap;

	if (clock->pmc &&
	    !(ts > clock->pmc_last_update &&
	      ts - clock->pmc_last_update < PMC_UPDATE_INTERVAL)) {
		if (run_pmc(clock, 0, 0, 1) > 0)
			clock->pmc_last_update = ts;
	}

	/* Handle leap seconds. */

	if (!clock->leap && !clock->leap_set)
		return 0;

	/* If the system clock is the master clock, get a time stamp from
	   it, as it is the clock which will include the leap second. */
	if (clock->clkid != CLOCK_REALTIME) {
		struct timespec tp;
		if (clock_gettime(CLOCK_REALTIME, &tp)) {
			pr_err("failed to read clock: %m");
			return -1;
		}
		ts = tp.tv_sec * NS_PER_SEC + tp.tv_nsec;
	}

	/* If the clock will be stepped, the time stamp has to be the
	   target time. Ignore possible 1 second error in UTC offset. */
	if (clock->clkid == CLOCK_REALTIME &&
	    clock->servo_state == SERVO_UNLOCKED) {
		ts -= offset + clock->sync_offset * NS_PER_SEC *
			clock->sync_offset_direction;
	}

	/* Suspend clock updates in the last second before midnight. */
	if (is_utc_ambiguous(ts)) {
		pr_info("clock update suspended due to leap second");
		return -1;
	}

	clock_leap = leap_second_status(ts, clock->leap_set,
					&clock->leap, &clock->sync_offset);

	if (clock->leap_set != clock_leap) {
		/* Only the system clock can leap. */
		if (clock->clkid == CLOCK_REALTIME && clock->kernel_leap)
			sysclk_set_leap(clock_leap);
		clock->leap_set = clock_leap;
	}

	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\n"
		"usage: %s [options]\n\n"
		" -c [dev|name]  slave clock (CLOCK_REALTIME)\n"
		" -d [dev]       master PPS device\n"
		" -s [dev|name]  master clock\n"
		" -E [pi|linreg] clock servo (pi)\n"
		" -P [kp]        proportional constant (0.7)\n"
		" -I [ki]        integration constant (0.3)\n"
		" -S [step]      step threshold (disabled)\n"
		" -F [step]      step threshold only on start (0.00002)\n"
		" -R [rate]      slave clock update rate in HZ (1.0)\n"
		" -N [num]       number of master clock readings per update (5)\n"
		" -O [offset]    slave-master time offset (0)\n"
		" -L [limit]     sanity frequency limit in ppb (200000000)\n"
		" -u [num]       number of clock updates in summary stats (0)\n"
		" -w             wait for ptp4l\n"
		" -n [num]       domain number (0)\n"
		" -x             apply leap seconds by servo instead of kernel\n"
		" -l [num]       set the logging level to 'num' (6)\n"
		" -m             print messages to stdout\n"
		" -q             do not print messages to the syslog\n"
		" -v             prints the software version and exits\n"
		" -h             prints this message and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *progname;
	clockid_t src = CLOCK_INVALID;
	int c, domain_number = 0, phc_readings = 5, pps_fd = -1;
	int max_ppb, r, wait_sync = 0, forced_sync_offset = 0;
	int print_level = LOG_INFO, use_syslog = 1, verbose = 0;
	int sanity_freq_limit = 200000000;
	enum servo_type servo = CLOCK_SERVO_PI;
	double ppb, phc_interval = 1.0, phc_rate;
	struct timespec phc_interval_tp;
	struct clock dst_clock = {
		.clkid = CLOCK_REALTIME,
		.servo_state = SERVO_UNLOCKED,
		.kernel_leap = 1,
	};

	configured_pi_kp = KP;
	configured_pi_ki = KI;

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv,
				  "c:d:s:E:P:I:S:F:R:N:O:L:i:u:wn:xl:mqvh"))) {
		switch (c) {
		case 'c':
			dst_clock.clkid = clock_open(optarg);
			break;
		case 'd':
			pps_fd = open(optarg, O_RDONLY);
			if (pps_fd < 0) {
				fprintf(stderr,
					"cannot open '%s': %m\n", optarg);
				return -1;
			}
			break;
		case 'i':
			fprintf(stderr,
				"'-i' has been deprecated. please use '-s' instead.\n");
		case 's':
			src = clock_open(optarg);
			break;
		case 'E':
			if (!strcasecmp(optarg, "pi")) {
				servo = CLOCK_SERVO_PI;
			} else if (!strcasecmp(optarg, "linreg")) {
				servo = CLOCK_SERVO_LINREG;
			} else {
				fprintf(stderr,
					"invalid servo name %s\n", optarg);
				return -1;
			}
			break;
		case 'P':
			if (get_arg_val_d(c, optarg, &configured_pi_kp,
					  0.0, DBL_MAX))
				return -1;
			break;
		case 'I':
			if (get_arg_val_d(c, optarg, &configured_pi_ki,
					  0.0, DBL_MAX))
				return -1;
			break;
		case 'S':
			if (get_arg_val_d(c, optarg, &servo_step_threshold,
					  0.0, DBL_MAX))
				return -1;
			break;
		case 'F':
			if (get_arg_val_d(c, optarg, &servo_first_step_threshold,
					  0.0, DBL_MAX))
				return -1;
			break;
		case 'R':
			if (get_arg_val_d(c, optarg, &phc_rate, 1e-9, DBL_MAX))
				return -1;
			phc_interval = 1.0 / phc_rate;
			break;
		case 'N':
			if (get_arg_val_i(c, optarg, &phc_readings, 1, INT_MAX))
				return -1;
			break;
		case 'O':
			if (get_arg_val_i(c, optarg, &dst_clock.sync_offset,
					  INT_MIN, INT_MAX))
				return -1;
			dst_clock.sync_offset_direction = -1;
			forced_sync_offset = 1;
			break;
		case 'L':
			if (get_arg_val_i(c, optarg, &sanity_freq_limit, 0, INT_MAX))
				return -1;
			break;
		case 'u':
			if (get_arg_val_ui(c, optarg, &dst_clock.stats_max_count,
					  0, UINT_MAX))
				return -1;
			break;
		case 'w':
			wait_sync = 1;
			break;
		case 'n':
			if (get_arg_val_i(c, optarg, &domain_number, 0, 255))
				return -1;
			break;
		case 'x':
			dst_clock.kernel_leap = 0;
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX))
				return -1;
			break;
		case 'm':
			verbose = 1;
			break;
		case 'q':
			use_syslog = 0;
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'h':
			usage(progname);
			return 0;
		default:
			goto bad_usage;
		}
	}

	if (pps_fd < 0 && src == CLOCK_INVALID) {
		fprintf(stderr,
			"valid source clock must be selected.\n");
		goto bad_usage;
	}

	if (dst_clock.clkid == CLOCK_INVALID) {
		fprintf(stderr,
			"valid destination clock must be selected.\n");
		goto bad_usage;
	}

	if (pps_fd >= 0 && dst_clock.clkid != CLOCK_REALTIME) {
		fprintf(stderr,
			"cannot use a pps device unless destination is CLOCK_REALTIME\n");
		goto bad_usage;
	}

	if (!wait_sync && !forced_sync_offset) {
		fprintf(stderr,
			"time offset must be specified using -w or -O\n");
		goto bad_usage;
	}

	if (dst_clock.stats_max_count > 0) {
		dst_clock.offset_stats = stats_create();
		dst_clock.freq_stats = stats_create();
		dst_clock.delay_stats = stats_create();
		if (!dst_clock.offset_stats ||
		    !dst_clock.freq_stats ||
		    !dst_clock.delay_stats) {
			fprintf(stderr, "failed to create stats");
			return -1;
		}
	}
	if (sanity_freq_limit) {
		dst_clock.sanity_check = clockcheck_create(sanity_freq_limit);
		if (!dst_clock.sanity_check) {
			fprintf(stderr, "failed to create clock check");
			return -1;
		}
	}

	print_set_progname(progname);
	print_set_verbose(verbose);
	print_set_syslog(use_syslog);
	print_set_level(print_level);

	if (wait_sync) {
		if (init_pmc(&dst_clock, domain_number))
			return -1;

		while (1) {
			r = run_pmc(&dst_clock, 1000,
				    wait_sync, !forced_sync_offset);
			if (r < 0)
				return -1;
			else if (r > 0)
				break;
			else
				pr_notice("Waiting for ptp4l...");
		}

		if (!forced_sync_offset) {
			if (src != CLOCK_REALTIME &&
			    dst_clock.clkid == CLOCK_REALTIME)
				dst_clock.sync_offset_direction = 1;
			else if (src == CLOCK_REALTIME &&
			    dst_clock.clkid != CLOCK_REALTIME)
				dst_clock.sync_offset_direction = -1;
			else
				dst_clock.sync_offset_direction = 0;
		}

		if (forced_sync_offset || !dst_clock.sync_offset_direction)
			close_pmc(&dst_clock);
	}

	clockadj_init(dst_clock.clkid);
	ppb = clockadj_get_freq(dst_clock.clkid);
	/* The reading may silently fail and return 0, reset the frequency to
	   make sure ppb is the actual frequency of the clock. */
	clockadj_set_freq(dst_clock.clkid, ppb);
	if (dst_clock.clkid == CLOCK_REALTIME) {
		sysclk_set_leap(0);
		max_ppb = sysclk_max_freq();
	} else {
		max_ppb = phc_max_adj(dst_clock.clkid);
		if (!max_ppb) {
			pr_err("clock is not adjustable");
			return -1;
		}
	}

	dst_clock.servo = servo_create(servo, -ppb, max_ppb, 0);

	if (pps_fd >= 0) {
		servo_sync_interval(dst_clock.servo, 1.0);
		return do_pps_loop(&dst_clock, pps_fd, src, phc_readings);
	}

	servo_sync_interval(dst_clock.servo, phc_interval);

	phc_interval_tp.tv_sec = phc_interval;
	phc_interval_tp.tv_nsec = (phc_interval - phc_interval_tp.tv_sec) * 1e9;

	if (dst_clock.clkid == CLOCK_REALTIME && src != CLOCK_REALTIME &&
	    SYSOFF_SUPPORTED == sysoff_probe(CLOCKID_TO_FD(src), phc_readings))
		return do_sysoff_loop(&dst_clock, src, &phc_interval_tp,
				      phc_readings);

	return do_phc_loop(&dst_clock, src, &phc_interval_tp, phc_readings);

bad_usage:
	usage(progname);
	return -1;
}
