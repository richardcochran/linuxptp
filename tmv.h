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
 * integer nanoseconds and a 32 bit signed integer containing
 * fractional (2^-16) nanoseconds, where the fractional part is
 * guaranteed to lie within the range [-0xffff,0xffff] and to have the
 * same sign as the integer part.
 */
typedef struct {
	int64_t ns;
	int32_t frac;
} tmv_t;

extern tmv_t tmv_add(tmv_t a, tmv_t b);
extern tmv_t tmv_div(tmv_t a, int divisor);
extern int tmv_cmp(tmv_t a, tmv_t b);
extern int tmv_sign(tmv_t x);
extern int tmv_is_zero(tmv_t x);
extern tmv_t tmv_sub(tmv_t a, tmv_t b);
extern tmv_t tmv_zero(void);
extern tmv_t correction_to_tmv(Integer64 c);
extern double tmv_dbl(tmv_t x);
extern tmv_t dbl_tmv(double x);
extern int64_t tmv_to_nanoseconds(tmv_t x);
extern TimeInterval tmv_to_TimeInterval(tmv_t x);
extern struct Timestamp tmv_to_Timestamp(tmv_t x);
extern tmv_t timespec_to_tmv(struct timespec ts);
extern tmv_t timestamp_to_tmv(struct timestamp ts);

#endif
