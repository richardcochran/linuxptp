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
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include <linux/pps.h>
#include <linux/ptp_clock.h>

#include "ds.h"
#include "fsm.h"
#include "missing.h"
#include "pi.h"
#include "pmc_common.h"
#include "print.h"
#include "servo.h"
#include "sk.h"
#include "sysoff.h"
#include "tlv.h"
#include "version.h"

#define KP 0.7
#define KI 0.3
#define NS_PER_SEC 1000000000LL

#define max_ppb  512000

#define PHC_PPS_OFFSET_LIMIT 10000000

static clockid_t clock_open(char *device)
{
	int fd;

	if (device[0] != '/') {
		if (!strcasecmp(device, "CLOCK_REALTIME"))
			return CLOCK_REALTIME;

		fprintf(stderr, "unknown clock %s\n", device);
		return CLOCK_INVALID;
	}

	fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "cannot open %s: %m\n", device);
		return CLOCK_INVALID;
	}
	return FD_TO_CLOCKID(fd);
}

static void clock_ppb(clockid_t clkid, double ppb)
{
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	tx.modes = ADJ_FREQUENCY;
	tx.freq = (long) (ppb * 65.536);
	if (clock_adjtime(clkid, &tx) < 0)
		fprintf(stderr, "failed to adjust the clock: %m\n");
}

static double clock_ppb_read(clockid_t clkid)
{
	double f = 0.0;
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	if (clock_adjtime(clkid, &tx) < 0)
		fprintf(stderr, "failed to read out the clock frequency adjustment: %m\n");
	else
		f = tx.freq / 65.536;
	return f;
}

static void clock_step(clockid_t clkid, int64_t ns)
{
	struct timex tx;
	int sign = 1;
	if (ns < 0) {
		sign = -1;
		ns *= -1;
	}
	memset(&tx, 0, sizeof(tx));
	tx.modes = ADJ_SETOFFSET | ADJ_NANO;
	tx.time.tv_sec  = sign * (ns / NS_PER_SEC);
	tx.time.tv_usec = sign * (ns % NS_PER_SEC);
	/*
	 * The value of a timeval is the sum of its fields, but the
	 * field tv_usec must always be non-negative.
	 */
	if (tx.time.tv_usec < 0) {
		tx.time.tv_sec  -= 1;
		tx.time.tv_usec += 1000000000;
	}
	if (clock_adjtime(clkid, &tx) < 0)
		fprintf(stderr, "failed to step clock: %m\n");
}

static int read_phc(clockid_t clkid, clockid_t sysclk, int readings,
		    int64_t *offset, uint64_t *ts)
{
	struct timespec tdst1, tdst2, tsrc;
	int i;
	int64_t interval, best_interval = INT64_MAX;

	/* Pick the quickest clkid reading. */
	for (i = 0; i < readings; i++) {
		if (clock_gettime(sysclk, &tdst1) ||
				clock_gettime(clkid, &tsrc) ||
				clock_gettime(sysclk, &tdst2)) {
			perror("clock_gettime");
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

	return 1;
}

struct clock {
	clockid_t clkid;
	struct servo *servo;
	FILE *log_file;
	const char *source_label;
};

static void update_clock(struct clock *clock, int64_t offset, uint64_t ts)
{
	enum servo_state state;
	double ppb;

	ppb = servo_sample(clock->servo, offset, ts, &state);

	switch (state) {
	case SERVO_UNLOCKED:
		break;
	case SERVO_JUMP:
		clock_step(clock->clkid, -offset);
		/* Fall through. */
	case SERVO_LOCKED:
		clock_ppb(clock->clkid, -ppb);
		break;
	}

	fprintf(clock->log_file, "%s %9" PRId64 " s%d %lld.%09llu adj %.2f\n",
		clock->source_label, offset, state,
		ts / NS_PER_SEC, ts % NS_PER_SEC, ppb);
	fflush(clock->log_file);
}

static int read_pps(int fd, int64_t *offset, uint64_t *ts)
{
	struct pps_fdata pfd;

	pfd.timeout.sec = 10;
	pfd.timeout.nsec = 0;
	pfd.timeout.flags = ~PPS_TIME_INVALID;
	if (ioctl(fd, PPS_FETCH, &pfd)) {
		perror("ioctl PPS_FETCH");
		return 0;
	}

	*ts = pfd.info.assert_tu.sec * NS_PER_SEC;
	*ts += pfd.info.assert_tu.nsec;

	*offset = *ts % NS_PER_SEC;
	if (*offset > NS_PER_SEC / 2)
		*offset -= NS_PER_SEC;

	return 1;
}

static int do_pps_loop(struct clock *clock, char *pps_device,
		       clockid_t src, int n_readings, int sync_offset)
{
	int64_t pps_offset, phc_offset;
	uint64_t pps_ts, phc_ts;
	int fd;

	clock->source_label = "pps";

	fd = open(pps_device, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open '%s': %m\n", pps_device);
		return -1;
	}

	while (1) {
		if (!read_pps(fd, &pps_offset, &pps_ts)) {
			continue;
		}

		/* If a PHC is available, use it to get the whole number
		   of seconds in the offset and PPS for the rest. */
		if (src != CLOCK_INVALID) {
			if (!read_phc(src, clock->clkid, n_readings,
				      &phc_offset, &phc_ts))
				return -1;
			
			/* Convert the time stamp to the PHC time. */
			phc_ts -= phc_offset;

			/* Check if it is close to the start of the second. */
			if (phc_ts % NS_PER_SEC > PHC_PPS_OFFSET_LIMIT) {
				fprintf(stderr, "PPS is not in sync with PHC"
					" (0.%09lld)\n", phc_ts % NS_PER_SEC);
				continue;
			}

			phc_ts = phc_ts / NS_PER_SEC * NS_PER_SEC;
			pps_offset = pps_ts - phc_ts;
			pps_offset -= sync_offset * NS_PER_SEC;
		}

		update_clock(clock, pps_offset, pps_ts);
	}
	close(fd);
	return 0;
}

static int do_sysoff_loop(struct clock *clock, clockid_t src,
			  int rate, int n_readings, int sync_offset)
{
	uint64_t ts;
	int64_t offset;
	int err = 0, fd = CLOCKID_TO_FD(src);

	clock->source_label = "sys";

	while (1) {
		usleep(1000000 / rate);
		if (sysoff_measure(fd, n_readings, &offset, &ts)) {
			err = -1;
			break;
		}
		offset -= sync_offset * NS_PER_SEC;
		update_clock(clock, offset, ts);
	}
	return err;
}

static int do_phc_loop(struct clock *clock, clockid_t src,
		       int rate, int n_readings, int sync_offset)
{
	uint64_t ts;
	int64_t offset;

	clock->source_label = "phc";

	while (1) {
		usleep(1000000 / rate);
		if (!read_phc(src, clock->clkid, n_readings, &offset, &ts)) {
			continue;
		}
		offset -= sync_offset * NS_PER_SEC;
		update_clock(clock, offset, ts);
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
	return ((struct management_tlv *) msg->management.suffix)->id;
}

static void *get_mgt_data(struct ptp_message *msg)
{
	return ((struct management_tlv *) msg->management.suffix)->data;
}

static int run_pmc(int wait_sync, int *utc_offset)
{
	struct ptp_message *msg;
	struct pmc *pmc;
	void *data;
#define N_FD 1
	struct pollfd pollfd[N_FD];
#define N_ID 2
	int cnt, i = 0, ds_done, ds_requested = 0;
	int ds_ids[N_ID] = {
		PORT_DATA_SET,
		TIME_PROPERTIES_DATA_SET
	};

	pmc = pmc_create(TRANS_UDS, "/var/run/phc2sys", 0, 0, 0);
	if (!pmc) {
		fprintf(stderr, "failed to create pmc\n");
		return -1;
	}

	while (i < N_ID) {
		pollfd[0].fd = pmc_get_transport_fd(pmc);
		pollfd[0].events = POLLIN|POLLPRI;
		if (!ds_requested)
			pollfd[0].events |= POLLOUT;

		cnt = poll(pollfd, N_FD, 1000);
		if (cnt < 0) {
			fprintf(stderr, "poll failed\n");
			return -1;
		}
		if (!cnt) {
			/* Request the data set again. */
			ds_requested = 0;
			fprintf(stderr, "Waiting for ptp4l...\n");
			continue;
		}

		if (pollfd[0].revents & POLLOUT) {
			pmc_send_get_action(pmc, ds_ids[i]);
			ds_requested = 1;
		}

		if (!(pollfd[0].revents & (POLLIN|POLLPRI)))
			continue;

		msg = pmc_recv(pmc);

		if (!msg)
			continue;

		if (!is_msg_mgt(msg) || get_mgt_id(msg) != ds_ids[i]) {
			msg_put(msg);
			continue;
		}

		data = get_mgt_data(msg);
		ds_done = 0;

		switch (get_mgt_id(msg)) {
		case PORT_DATA_SET:
			if (!wait_sync)
				ds_done = 1;

			switch (((struct portDS *)data)->portState) {
			case PS_MASTER:
			case PS_SLAVE:
				ds_done = 1;
				break;
			}

			break;
		case TIME_PROPERTIES_DATA_SET:
			*utc_offset = ((struct timePropertiesDS *)data)->
					currentUtcOffset;
			ds_done = 1;
			break;
		}

		if (ds_done) {
			/* Proceed with the next data set. */
			i++;
			ds_requested = 0;
		}
		msg_put(msg);
	}

	pmc_destroy(pmc);

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
		" -i [iface]     master clock by network interface\n"
		" -P [kp]        proportional constant (0.7)\n"
		" -I [ki]        integration constant (0.3)\n"
		" -S [step]      step threshold (disabled)\n"
		" -R [rate]      slave clock update rate in HZ (1)\n"
		" -N [num]       number of master clock readings per update (5)\n"
		" -O [offset]    slave-master time offset (0)\n"
		" -w             wait for ptp4l\n"
		" -h             prints this message and exits\n"
		" -v             prints the software version and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	char *device = NULL, *progname, *ethdev = NULL;
	clockid_t src = CLOCK_INVALID;
	int c, phc_readings = 5, phc_rate = 1, sync_offset = 0;
	int wait_sync = 0, forced_sync_offset = 0;
	double ppb;
	struct clock dst_clock = {
		.clkid = CLOCK_REALTIME,
		.log_file = stdout
	};

	configured_pi_kp = KP;
	configured_pi_ki = KI;

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "c:d:hs:P:I:S:R:N:O:i:wv"))) {
		switch (c) {
		case 'c':
			dst_clock.clkid = clock_open(optarg);
			break;
		case 'd':
			device = optarg;
			break;
		case 's':
			src = clock_open(optarg);
			break;
		case 'P':
			configured_pi_kp = atof(optarg);
			break;
		case 'I':
			configured_pi_ki = atof(optarg);
			break;
		case 'S':
			configured_pi_offset = atof(optarg);
			break;
		case 'R':
			phc_rate = atoi(optarg);
			break;
		case 'N':
			phc_readings = atoi(optarg);
			break;
		case 'O':
			sync_offset = atoi(optarg);
			forced_sync_offset = 1;
			break;
		case 'i':
			ethdev = optarg;
			break;
		case 'w':
			wait_sync = 1;
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'h':
			usage(progname);
			return 0;
		default:
			usage(progname);
			return -1;
		}
	}

	if (src == CLOCK_INVALID && ethdev) {
		struct sk_ts_info ts_info;
		char phc_device[16];
		if (sk_get_ts_info(ethdev, &ts_info) || !ts_info.valid) {
			fprintf(stderr, "can't autodiscover PHC device\n");
			return -1;
		}
		if (ts_info.phc_index < 0) {
			fprintf(stderr, "interface %s doesn't have a PHC\n", ethdev);
			return -1;
		}
		sprintf(phc_device, "/dev/ptp%d", ts_info.phc_index);
		src = clock_open(phc_device);
	}
	if (!(device || src != CLOCK_INVALID) ||
	    dst_clock.clkid == CLOCK_INVALID ||
	    (device && dst_clock.clkid != CLOCK_REALTIME)) {
		usage(progname);
		return -1;
	}

	print_set_progname(progname);
	print_set_verbose(1);
	print_set_syslog(0);

	if (wait_sync) {
		int ptp_utc_offset;

		run_pmc(wait_sync, &ptp_utc_offset);

		if (!forced_sync_offset) {
			if (src != CLOCK_REALTIME &&
			    dst_clock.clkid == CLOCK_REALTIME)
				sync_offset = -ptp_utc_offset;
			else if (src == CLOCK_REALTIME &&
			    dst_clock.clkid != CLOCK_REALTIME)
				sync_offset = ptp_utc_offset;
		}
	}

	ppb = clock_ppb_read(dst_clock.clkid);
	/* The reading may silently fail and return 0, reset the frequency to
	   make sure ppb is the actual frequency of the clock. */
	clock_ppb(dst_clock.clkid, ppb);

	dst_clock.servo = servo_create(CLOCK_SERVO_PI, -ppb, max_ppb, 0);

	if (device)
		return do_pps_loop(&dst_clock, device, src,
				   phc_readings, sync_offset);

	if (dst_clock.clkid == CLOCK_REALTIME &&
	    SYSOFF_SUPPORTED == sysoff_probe(CLOCKID_TO_FD(src), phc_readings))
		return do_sysoff_loop(&dst_clock, src, phc_rate,
				      phc_readings, sync_offset);

	return do_phc_loop(&dst_clock, src, phc_rate,
			   phc_readings, sync_offset);
}
