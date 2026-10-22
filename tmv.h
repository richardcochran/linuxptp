/**
 * @file tmv.h
 * @brief Implements an abstract time value type.
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
#ifndef HAVE_TMV_H
#define HAVE_TMV_H

#include <linux/ptp_clock.h>
#include <time.h>

#include "ddt.h"
#include "pdt.h"

#define NS_PER_SEC 1000000000LL
#define MIN_TMV_TO_TIMEINTERVAL 0xFFFF800000000000ll
#define MAX_TMV_TO_TIMEINTERVAL 0x00007FFFFFFFFFFFll

#define TMV_FRAC_PER_NS 65536
#define TMV_FRAC_MASK   0xffff

/**
 * We implement the time value as a 64 bit signed integer containing
 * nanoseconds, plus fractional nanoseconds in units of 2^-16 ns, the
 * scale of TimeInterval.  The nanoseconds alone cannot be scaled by 2^16
 * without overflowing for absolute PTP times.
 *
 * The fraction is normalized into [0, 1) ns, so the value is exactly
 * ns + frac / 65536 and the integer part is a floor: -0.5 ns is
 * (ns = -1, frac = 32768).
 */
typedef struct {
	int64_t ns;
	int32_t frac;
} tmv_t;

/**
 * Build a time value from nanoseconds and a fraction in units of
 * 2^-16 ns, which may be negative or exceed one nanosecond.
 */
static inline tmv_t tmv_normalize(int64_t ns, int64_t frac)
{
	tmv_t t;
	t.ns = (uint64_t)ns + (uint64_t)(frac >> 16);
	t.frac = frac & TMV_FRAC_MASK;
	return t;
}

static inline tmv_t tmv_add(tmv_t a, tmv_t b)
{
	return tmv_normalize((uint64_t)a.ns + (uint64_t)b.ns,
			     (int64_t)a.frac + (int64_t)b.frac);
}

static inline tmv_t tmv_div(tmv_t a, int divisor)
{
	int64_t quotient = a.ns / divisor;
	int64_t remainder = a.ns % divisor;

	return tmv_normalize(quotient,
			     (remainder * TMV_FRAC_PER_NS + a.frac) / divisor);
}

static inline int tmv_cmp(tmv_t a, tmv_t b)
{
	if (a.ns != b.ns) {
		return a.ns > b.ns ? +1 : -1;
	}
	return a.frac == b.frac ? 0 : a.frac > b.frac ? +1 : -1;
}

static inline int tmv_sign(tmv_t x)
{
	if (x.ns) {
		return x.ns > 0 ? +1 : -1;
	}
	return x.frac ? +1 : 0;
}

static inline int tmv_is_zero(tmv_t x)
{
	return x.ns == 0 && x.frac == 0 ? 1 : 0;
}

static inline tmv_t tmv_sub(tmv_t a, tmv_t b)
{
	return tmv_normalize((uint64_t)a.ns - (uint64_t)b.ns,
			     (int64_t)a.frac - (int64_t)b.frac);
}

static inline tmv_t tmv_zero(void)
{
	tmv_t t = { 0, 0 };
	return t;
}

static inline tmv_t correction_to_tmv(Integer64 c)
{
	return tmv_normalize(0, c);
}

/**
 * Return the fractional nanoseconds of a time value in units of
 * 2^-16 ns, in the range [0, 65536).
 */
static inline Integer64 tmv_frac(tmv_t x)
{
	return x.frac;
}

static inline double tmv_dbl(tmv_t x)
{
	return (double) x.ns + (double) x.frac / TMV_FRAC_PER_NS;
}

static inline tmv_t dbl_tmv(double x)
{
	int64_t ns = (int64_t) x;

	return tmv_normalize(ns, (int64_t)((x - (double) ns) *
					   TMV_FRAC_PER_NS));
}

static inline int64_t tmv_to_nanoseconds(tmv_t x)
{
	return x.ns;
}

static inline tmv_t nanoseconds_to_tmv(int64_t ns)
{
	tmv_t t;
	t.ns = ns;
	t.frac = 0;
	return t;
}

static inline TimeInterval tmv_to_TimeInterval(tmv_t x)
{
	if (x.ns < (int64_t)MIN_TMV_TO_TIMEINTERVAL) {
		return MIN_TMV_TO_TIMEINTERVAL << 16;
	} else if (x.ns > (int64_t)MAX_TMV_TO_TIMEINTERVAL) {
		return MAX_TMV_TO_TIMEINTERVAL << 16;
	}
	return ((uint64_t)x.ns << 16) + (uint64_t)x.frac;
}

/* Drops the fraction, see tmv_frac(). */
static inline struct Timestamp tmv_to_Timestamp(tmv_t x)
{
	struct Timestamp result;
	uint64_t sec, nsec;

	sec  = x.ns / 1000000000ULL;
	nsec = x.ns % 1000000000ULL;

	result.seconds_lsb = sec & 0xFFFFFFFF;
	result.seconds_msb = (sec >> 32) & 0xFFFF;
	result.nanoseconds = nsec;

	return result;
}

static inline tmv_t timespec_to_tmv(struct timespec ts)
{
	tmv_t t;
	t.ns = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
	t.frac = 0;
	return t;
}

static inline struct timespec tmv_to_timespec(tmv_t t)
{
	struct timespec ts;

	ts.tv_sec  = t.ns / NS_PER_SEC;
	ts.tv_nsec = t.ns % NS_PER_SEC;

	return ts;
}

static inline tmv_t timestamp_to_tmv(struct timestamp ts)
{
	tmv_t t;
	t.ns = ts.sec * NS_PER_SEC + ts.nsec;
	t.frac = 0;
	return t;
}

static inline tmv_t pct_to_tmv(struct ptp_clock_time pct)
{
	tmv_t t;
	t.ns = pct.sec * NS_PER_SEC + pct.nsec;
	t.frac = 0;
	return t;
}

#endif
