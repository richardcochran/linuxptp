/**
 * @file tmv.c
 * @brief Implements an abstract time value type.
 * @note Copyright (C) 2018 Michael Brown <mbrown@fensystems.co.uk>
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
#include <math.h>
#include <time.h>

#include "ddt.h"
#include "pdt.h"
#include "msg.h"
#include "tmv.h"

#define NS_BITS 16
#define NS_FRAC (1<<NS_BITS)

static tmv_t tmv_normalize(int64_t ns, int32_t frac)
{
	tmv_t t;

	while ((frac > NS_FRAC) || (frac > 0 && ns < 0)) {
		frac -= NS_FRAC;
		ns++;
	}
	while ((frac < -NS_FRAC) || (frac < 0 && ns > 0)) {
		frac += NS_FRAC;
		ns--;
	}
	t.ns = ns;
	t.frac = frac;
	return t;
}

tmv_t tmv_add(tmv_t a, tmv_t b)
{
	return tmv_normalize(a.ns + b.ns, a.frac + b.frac);
}

tmv_t tmv_div(tmv_t a, int divisor)
{
	int64_t q;
	int64_t r;
	q = a.ns / divisor;
	r = a.ns % divisor;
	return tmv_normalize(q, (r * NS_FRAC + a.frac) / divisor);
}

int tmv_cmp(tmv_t a, tmv_t b)
{
	if (a.ns == b.ns) {
		return a.frac == b.frac ? 0 : a.frac > b.frac ? +1 : -1;
	} else {
		return a.ns > b.ns ? +1 : -1;
	}
}

int tmv_sign(tmv_t x)
{
	if (x.ns == 0) {
		return x.frac == 0 ? 0 : x.frac > 0 ? +1 : -1;
	} else {
		return x.ns > 0 ? +1 : -1;
	}
}

int tmv_is_zero(tmv_t x)
{
	return x.ns == 0 && x.frac == 0 ? 1 : 0;
}

tmv_t tmv_sub(tmv_t a, tmv_t b)
{
	return tmv_normalize(a.ns - b.ns, a.frac - b.frac);
}

tmv_t tmv_zero(void)
{
	tmv_t t = { 0, 0 };
	return t;
}

tmv_t correction_to_tmv(Integer64 c)
{
	return tmv_normalize(c / NS_FRAC, c % NS_FRAC);
}

double tmv_dbl(tmv_t x)
{
	return (double) x.ns + (double) x.frac / NS_FRAC;
}

tmv_t dbl_tmv(double x)
{
	double ns;
	double frac;
	frac = modf(x, &ns);
	return tmv_normalize(ns, frac * NS_FRAC);
}

int64_t tmv_to_nanoseconds(tmv_t x)
{
	return x.ns;
}

TimeInterval tmv_to_TimeInterval(tmv_t x)
{
	return x.ns * NS_FRAC + x.frac;
}

struct Timestamp tmv_to_Timestamp(tmv_t x)
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

tmv_t timespec_to_tmv(struct timespec ts)
{
	tmv_t t;
	t.ns = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
	t.frac = 0;
	return t;
}

tmv_t timestamp_to_tmv(struct timestamp ts)
{
	tmv_t t;
	t.ns = ts.sec * NS_PER_SEC + ts.nsec;
	t.frac = 0;
	return t;
}

tmv_t timehires_to_tmv(struct timehires ts)
{
	return tmv_normalize(ts.tv_nsec, ts.tv_frac >>
				(8*sizeof(ts.tv_frac)-NS_BITS));
}

