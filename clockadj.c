/**
 * @file clockadj.c
 * @note Copyright (C) 2013 Richard Cochran <richardcochran@gmail.com>
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

#include <string.h>

#include "clockadj.h"
#include "missing.h"
#include "print.h"

#define NS_PER_SEC 1000000000LL

static int realtime_leap_bit;

void clockadj_set_freq(clockid_t clkid, double freq)
{
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	tx.modes = ADJ_FREQUENCY;
	tx.freq = (long) (freq * 65.536);
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to adjust the clock: %m");
}

double clockadj_get_freq(clockid_t clkid)
{
	double f = 0.0;
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to read out the clock frequency adjustment: %m");
	else
		f = tx.freq / 65.536;
	return f;
}

void clockadj_step(clockid_t clkid, int64_t step)
{
	struct timex tx;
	int sign = 1;
	if (step < 0) {
		sign = -1;
		step *= -1;
	}
	memset(&tx, 0, sizeof(tx));
	tx.modes = ADJ_SETOFFSET | ADJ_NANO;
	tx.time.tv_sec  = sign * (step / NS_PER_SEC);
	tx.time.tv_usec = sign * (step % NS_PER_SEC);
	/*
	 * The value of a timeval is the sum of its fields, but the
	 * field tv_usec must always be non-negative.
	 */
	if (tx.time.tv_usec < 0) {
		tx.time.tv_sec  -= 1;
		tx.time.tv_usec += 1000000000;
	}
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to step clock: %m");
}

void sysclk_set_leap(int leap)
{
	clockid_t clkid = CLOCK_REALTIME;
	struct timex tx;
	const char *m = NULL;
	memset(&tx, 0, sizeof(tx));
	tx.modes = ADJ_STATUS;
	switch (leap) {
	case -1:
		tx.status = STA_DEL;
		m = "clock set to delete leap second at midnight (UTC)";
		break;
	case 1:
		tx.status = STA_INS;
		m = "clock set to insert leap second at midnight (UTC)";
		break;
	default:
		tx.status = 0;
	}
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to set the clock status: %m");
	else if (m)
		pr_notice(m);
	realtime_leap_bit = tx.status;
}

int sysclk_max_freq(void)
{
	clockid_t clkid = CLOCK_REALTIME;
	int f = 0;
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to read out the clock maximum adjustment: %m");
	else
		f = tx.tolerance / 65.536;
	if (!f)
		f = 500000;
	return f;
}

void sysclk_set_sync(void)
{
	clockid_t clkid = CLOCK_REALTIME;
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	/* Clear the STA_UNSYNC flag from the status and keep the maxerror
	   value (which is increased automatically by 500 ppm) below 16 seconds
	   to avoid getting the STA_UNSYNC flag back. */
	tx.modes = ADJ_STATUS | ADJ_MAXERROR;
	tx.status = realtime_leap_bit;
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to set clock status and maximum error: %m");
}
