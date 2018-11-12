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
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/ptp_clock.h>

#include "print.h"
#include "sysoff.h"

#define NS_PER_SEC 1000000000LL

#ifdef PTP_SYS_OFFSET

static int64_t pctns(struct ptp_clock_time *t)
{
	return t->sec * NS_PER_SEC + t->nsec;
}

static struct {
	int64_t interval;
	int64_t offset;
	uint64_t timestamp;
} samples[PTP_MAX_SAMPLES];

static int sysoff_precise(int fd, int64_t *result, uint64_t *ts)
{
#ifdef PTP_SYS_OFFSET_PRECISE
	struct ptp_sys_offset_precise pso;
	memset(&pso, 0, sizeof(pso));
	if (ioctl(fd, PTP_SYS_OFFSET_PRECISE, &pso)) {
		pr_debug("ioctl PTP_SYS_OFFSET_PRECISE: %m");
		return SYSOFF_RUN_TIME_MISSING;
	}
	*result = pctns(&pso.sys_realtime) - pctns(&pso.device);
	*ts = pctns(&pso.sys_realtime);
	return SYSOFF_PRECISE;
#else
	return SYSOFF_COMPILE_TIME_MISSING;
#endif
}

static void insertion_sort(int length, int64_t interval, int64_t offset, uint64_t ts)
{
	int i = length - 1;
	while (i >= 0) {
		if (samples[i].interval < interval)
			break;
		samples[i+1] = samples[i];
		i--;
	}
	samples[i+1].interval = interval;
	samples[i+1].offset = offset;
	samples[i+1].timestamp = ts;
}

static int64_t sysoff_estimate(struct ptp_clock_time *pct, int n_samples,
			       uint64_t *ts, int64_t *delay)
{
	int64_t t1, t2, tp;
	int64_t interval, offset;
	int i;

	for (i = 0; i < n_samples; i++) {
		t1 = pctns(&pct[2*i]);
		tp = pctns(&pct[2*i+1]);
		t2 = pctns(&pct[2*i+2]);
		interval = t2 - t1;
		offset = (t2 + t1) / 2 - tp;
		insertion_sort(i, interval, offset, (t2 + t1) / 2);
	}
	*ts = samples[0].timestamp;
	*delay = samples[0].interval;
	return samples[0].offset;
}

static int sysoff_basic(int fd, int n_samples,
			int64_t *result, uint64_t *ts, int64_t *delay)
{
	struct ptp_sys_offset pso;
	memset(&pso, 0, sizeof(pso));
	pso.n_samples = n_samples;
	if (ioctl(fd, PTP_SYS_OFFSET, &pso)) {
		perror("ioctl PTP_SYS_OFFSET");
		return SYSOFF_RUN_TIME_MISSING;
	}
	*result = sysoff_estimate(pso.ts, n_samples, ts, delay);
	return SYSOFF_BASIC;
}

int sysoff_measure(int fd, int method, int n_samples,
		   int64_t *result, uint64_t *ts, int64_t *delay)
{
	switch (method) {
	case SYSOFF_PRECISE:
		*delay = 0;
		return sysoff_precise(fd, result, ts);
	case SYSOFF_BASIC:
		return sysoff_basic(fd, n_samples, result, ts, delay);
	}
	return SYSOFF_COMPILE_TIME_MISSING;
}

int sysoff_probe(int fd, int n_samples)
{
	int64_t junk, delay;
	uint64_t ts;
	int i;

	if (n_samples > PTP_MAX_SAMPLES) {
		fprintf(stderr, "warning: %d exceeds kernel max readings %d\n",
			n_samples, PTP_MAX_SAMPLES);
		fprintf(stderr, "falling back to clock_gettime method\n");
		return SYSOFF_RUN_TIME_MISSING;
	}

	for (i = 0; i < SYSOFF_LAST; i++) {
		if (sysoff_measure(fd, i, n_samples, &junk, &ts, &delay) < 0)
			continue;
		return i;
	}

	return SYSOFF_RUN_TIME_MISSING;
}

#else /* !PTP_SYS_OFFSET */

int sysoff_measure(int fd, int n_samples,
		   int64_t *result, uint64_t *ts, int64_t *delay)
{
	return SYSOFF_COMPILE_TIME_MISSING;
}

int sysoff_probe(int fd, int n_samples)
{
	return SYSOFF_COMPILE_TIME_MISSING;
}

#endif /* PTP_SYS_OFFSET */
