/**
 * @file sysoff.c
 * @brief Implements the system offset estimation method.
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
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/ptp_clock.h>

#include "print.h"
#include "sysoff.h"

#define NS_PER_SEC 1000000000LL

static void print_ioctl_error(const char *name)
{
	if (errno == EOPNOTSUPP)
		pr_debug("ioctl %s: %s", name, strerror(errno));
	else
		pr_err("ioctl %s: %s", name, strerror(errno));
}

static int64_t pctns(struct ptp_clock_time *t)
{
	return t->sec * NS_PER_SEC + t->nsec;
}

static int sysoff_precise(int fd, int64_t *result, uint64_t *ts)
{
	struct ptp_sys_offset_precise pso;
	memset(&pso, 0, sizeof(pso));
	if (ioctl(fd, PTP_SYS_OFFSET_PRECISE, &pso)) {
		print_ioctl_error("PTP_SYS_OFFSET_PRECISE");
		return -errno;
	}
	*result = pctns(&pso.sys_realtime) - pctns(&pso.device);
	*ts = pctns(&pso.sys_realtime);
	return 0;
}

static int64_t sysoff_estimate(struct ptp_clock_time *pct, int extended,
			       int n_samples, uint64_t *ts, int64_t *delay)
{
	int64_t t1, t2, tp;
	int64_t interval, timestamp, offset;
	int64_t shortest_interval, best_timestamp, best_offset;
	int i = 0;

	if (extended) {
		t1 = pctns(&pct[3*i]);
		tp = pctns(&pct[3*i+1]);
		t2 = pctns(&pct[3*i+2]);
	} else {
		t1 = pctns(&pct[2*i]);
		tp = pctns(&pct[2*i+1]);
		t2 = pctns(&pct[2*i+2]);
	}
	shortest_interval = t2 - t1;
	best_timestamp = (t2 + t1) / 2;
	best_offset = best_timestamp - tp;

	for (i = 1; i < n_samples; i++) {
		if (extended) {
			t1 = pctns(&pct[3*i]);
			tp = pctns(&pct[3*i+1]);
			t2 = pctns(&pct[3*i+2]);
		} else {
			t1 = pctns(&pct[2*i]);
			tp = pctns(&pct[2*i+1]);
			t2 = pctns(&pct[2*i+2]);
		}
		interval = t2 - t1;
		timestamp = (t2 + t1) / 2;
		offset = timestamp - tp;
		if (interval < shortest_interval) {
			shortest_interval = interval;
			best_timestamp = timestamp;
			best_offset = offset;
		}
	}
	*ts = best_timestamp;
	*delay = shortest_interval;
	return best_offset;
}

static int sysoff_extended(int fd, int n_samples,
			   int64_t *result, uint64_t *ts, int64_t *delay)
{
	struct ptp_sys_offset_extended pso;
	memset(&pso, 0, sizeof(pso));
	pso.n_samples = n_samples;
	if (ioctl(fd, PTP_SYS_OFFSET_EXTENDED, &pso)) {
		print_ioctl_error("PTP_SYS_OFFSET_EXTENDED");
		return -errno;
	}
	*result = sysoff_estimate(&pso.ts[0][0], 1, n_samples, ts, delay);
	return 0;
}

static int sysoff_basic(int fd, int n_samples,
			int64_t *result, uint64_t *ts, int64_t *delay)
{
	struct ptp_sys_offset pso;
	memset(&pso, 0, sizeof(pso));
	pso.n_samples = n_samples;
	if (ioctl(fd, PTP_SYS_OFFSET, &pso)) {
		print_ioctl_error("PTP_SYS_OFFSET");
		return -errno;
	}
	*result = sysoff_estimate(pso.ts, 0, n_samples, ts, delay);
	return 0;
}

int sysoff_measure(int fd, int method, int n_samples,
		   int64_t *result, uint64_t *ts, int64_t *delay)
{
	switch (method) {
	case SYSOFF_PRECISE:
		*delay = 0;
		return sysoff_precise(fd, result, ts);
	case SYSOFF_EXTENDED:
		return sysoff_extended(fd, n_samples, result, ts, delay);
	case SYSOFF_BASIC:
		return sysoff_basic(fd, n_samples, result, ts, delay);
	}
	return -EOPNOTSUPP;
}

int sysoff_probe(int fd, int n_samples)
{
	int64_t junk, delay;
	int i, j, err;
	uint64_t ts;

	if (n_samples > PTP_MAX_SAMPLES) {
		fprintf(stderr, "warning: %d exceeds kernel max readings %d\n",
			n_samples, PTP_MAX_SAMPLES);
		fprintf(stderr, "falling back to clock_gettime method\n");
		return SYSOFF_RUN_TIME_MISSING;
	}

	for (i = 0; i < SYSOFF_LAST; i++) {
		for (j = 0; j < 3; j++) {
			err = sysoff_measure(fd, i, n_samples, &junk, &ts,
					     &delay);
			if (err == -EBUSY)
				continue;
			if (err)
				break;
			return i;
		}
	}

	return SYSOFF_RUN_TIME_MISSING;
}
