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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/pps.h>
#include <linux/ptp_clock.h>

#include "missing.h"
#include "sk.h"

#define KP 0.7
#define KI 0.3
#define NS_PER_SEC 1000000000LL

#define max_ppb  512000
#define min_ppb -512000

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

struct servo {
	uint64_t saved_ts;
	int64_t saved_offset;
	double drift;
	enum {
		SAMPLE_0, SAMPLE_1, SAMPLE_2, SAMPLE_3, SAMPLE_N
	} state;
};

static struct servo servo;

static void show_servo(FILE *fp, const char *label, int64_t offset, uint64_t ts)
{
	fprintf(fp, "%s %9lld s%d %lld.%09llu drift %.2f\n", label, offset,
		servo.state, ts / NS_PER_SEC, ts % NS_PER_SEC, servo.drift);
	fflush(fp);
}

static void do_servo(struct servo *srv, clockid_t dst,
		     int64_t offset, uint64_t ts, double kp, double ki)
{
	double ki_term, ppb;

	switch (srv->state) {
	case SAMPLE_0:
		clock_ppb(dst, 0.0);
		srv->saved_offset = offset;
		srv->saved_ts = ts;
		srv->state = SAMPLE_1;
		break;
	case SAMPLE_1:
		srv->state = SAMPLE_2;
		break;
	case SAMPLE_2:
		srv->state = SAMPLE_3;
		break;
	case SAMPLE_3:
		srv->drift = (offset - srv->saved_offset) * 1e9 /
			(ts - srv->saved_ts);
		clock_ppb(dst, -srv->drift);
		clock_step(dst, -offset);
		srv->state = SAMPLE_N;
		break;
	case SAMPLE_N:
		ki_term = ki * offset;
		ppb = kp * offset + srv->drift + ki_term;
		if (ppb < min_ppb) {
			ppb = min_ppb;
		} else if (ppb > max_ppb) {
			ppb = max_ppb;
		} else {
			srv->drift += ki_term;
		}
		clock_ppb(dst, -ppb);
		break;
	}
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

static int do_pps_loop(char *pps_device, double kp, double ki, clockid_t dst)
{
	int64_t pps_offset;
	uint64_t pps_ts;
	int fd;

	fd = open(pps_device, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open '%s': %m\n", pps_device);
		return -1;
	}
	while (1) {
		if (!read_pps(fd, &pps_offset, &pps_ts)) {
			continue;
		}
		do_servo(&servo, dst, pps_offset, pps_ts, kp, ki);
		show_servo(stdout, "pps", pps_offset, pps_ts);
	}
	close(fd);
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
		" -R [rate]      slave clock update rate in HZ (1)\n"
		" -N [num]       number of master clock readings per update (5)\n"
		" -O [offset]    slave-master time offset (0)\n"
		" -h             prints this message and exits\n"
		"\n",
		progname);
}

int main(int argc, char *argv[])
{
	double kp = KP, ki = KI;
	char *device = NULL, *progname, *ethdev = NULL;
	clockid_t src = CLOCK_INVALID, dst = CLOCK_REALTIME;
	uint64_t phc_ts;
	int64_t phc_offset;
	int c, phc_readings = 5, phc_rate = 1, sync_offset = 0;

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv, "c:d:hs:P:I:R:N:O:i:"))) {
		switch (c) {
		case 'c':
			dst = clock_open(optarg);
			break;
		case 'd':
			device = optarg;
			break;
		case 's':
			src = clock_open(optarg);
			break;
		case 'P':
			kp = atof(optarg);
			break;
		case 'I':
			ki = atof(optarg);
			break;
		case 'R':
			phc_rate = atoi(optarg);
			break;
		case 'N':
			phc_readings = atoi(optarg);
			break;
		case 'O':
			sync_offset = atoi(optarg);
			break;
		case 'i':
			ethdev = optarg;
			break;
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
		sprintf(phc_device, "/dev/ptp%d", ts_info.phc_index);
		src = clock_open(phc_device);
	}
	if (!(device || src != CLOCK_INVALID) || dst == CLOCK_INVALID) {
		usage(progname);
		return -1;
	}
	if (src != CLOCK_INVALID) {
		struct timespec now;
		if (clock_gettime(src, &now))
			perror("clock_gettime");
		now.tv_sec += sync_offset;
		if (clock_settime(dst, &now))
			perror("clock_settime");
	}

	if (device)
		return do_pps_loop(device, kp, ki, dst);

	while (1) {
		usleep(1000000 / phc_rate);
		if (!read_phc(src, dst, phc_readings, &phc_offset, &phc_ts)) {
			continue;
		}
		phc_offset -= sync_offset * NS_PER_SEC;
		do_servo(&servo, dst, phc_offset, phc_ts, kp, ki);
		show_servo(stdout, "phc", phc_offset, phc_ts);
	}
	return 0;
}
