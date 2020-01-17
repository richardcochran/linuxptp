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

#include <time.h>

#include "ddt.h"
#include "pdt.h"

#define NS_PER_SEC 1000000000LL
#define MIN_TMV_TO_TIMEINTERVAL 0xFFFF800000000000ll
#define MAX_TMV_TO_TIMEINTERVAL 0x00007FFFFFFFFFFFll

/**
 * We implement the time value as a 64 bit signed integer containing
 * nanoseconds. Using this representation, we could really spare the
 * arithmetic functions such as @ref tmv_add() and the like, and just
 * use plain old math operators in the code.
 *
 * However, we are going to be a bit pedantic here and enforce the
 * use of the these functions, so that we can easily upgrade the code
 * to a finer representation later on. In that way, we can make use of
 * the fractional nanosecond parts of the correction fields, if and
 * when people start asking for them.
 */
typedef struct {
	int64_t ns;
} tmv_t;

static inline tmv_t tmv_add(tmv_t a, tmv_t b)
{
	tmv_t t;
	t.ns = a.ns + b.ns;
	return t;
}

static inline tmv_t tmv_div(tmv_t a, int divisor)
{
	tmv_t t;
	t.ns = a.ns / divisor;
	return t;
}

static inline int tmv_cmp(tmv_t a, tmv_t b)
{
	return a.ns == b.ns ? 0 : a.ns > b.ns ? +1 : -1;
}

static inline int tmv_sign(tmv_t x)
{
	return x.ns == 0 ? 0 : x.ns > 0 ? +1 : -1;
}

static inline int tmv_is_zero(tmv_t x)
{
	return x.ns == 0 ? 1 : 0;
}

static inline tmv_t tmv_sub(tmv_t a, tmv_t b)
{
	tmv_t t;
	t.ns = a.ns - b.ns;
	return t;
}

static inline tmv_t tmv_zero(void)
{
	tmv_t t = { 0 };
	return t;
}

static inline tmv_t correction_to_tmv(Integer64 c)
{
	tmv_t t;
	t.ns = (c >> 16);
	return t;
}

static inline double tmv_dbl(tmv_t x)
{
	return (double) x.ns;
}

static inline tmv_t dbl_tmv(double x)
{
	tmv_t t;
	t.ns = x;
	return t;
}

static inline int64_t tmv_to_nanoseconds(tmv_t x)
{
	return x.ns;
}

static inline TimeInterval tmv_to_TimeInterval(tmv_t x)
{
	if (x.ns < (int64_t)MIN_TMV_TO_TIMEINTERVAL) {
		return MIN_TMV_TO_TIMEINTERVAL << 16;
	} else if (x.ns > (int64_t)MAX_TMV_TO_TIMEINTERVAL) {
		return MAX_TMV_TO_TIMEINTERVAL << 16;
	}
	return x.ns << 16;
}

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
	return t;
}

#endif
