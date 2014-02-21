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
typedef int64_t tmv_t;

static inline tmv_t tmv_add(tmv_t a, tmv_t b)
{
	return a + b;
}

static inline tmv_t tmv_div(tmv_t a, int divisor)
{
	return a / divisor;
}

static inline int tmv_eq(tmv_t a, tmv_t b)
{
	return a == b ? 1 : 0;
}

static inline int tmv_is_zero(tmv_t x)
{
	return x == ((tmv_t) 0) ? 1 : 0;
}

static inline tmv_t tmv_sub(tmv_t a, tmv_t b)
{
	return a - b;
}

static inline tmv_t tmv_zero(void)
{
	return (tmv_t) 0;
}

static inline tmv_t correction_to_tmv(Integer64 c)
{
	return c >> 16;
}

static inline double tmv_dbl(tmv_t x)
{
	return (double) x;
}

static inline tmv_t dbl_tmv(double x)
{
	return (tmv_t) x;
}

static inline int64_t tmv_to_nanoseconds(tmv_t x)
{
	return x;
}

static inline TimeInterval tmv_to_TimeInterval(tmv_t x)
{
	return x << 16;
}

static inline tmv_t timespec_to_tmv(struct timespec ts)
{
	return ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static inline tmv_t timestamp_to_tmv(struct timestamp ts)
{
	return ts.sec * NS_PER_SEC + ts.nsec;
}

#endif
