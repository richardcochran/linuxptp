/**
 * @file mave.h
 * @brief Implements a moving average.
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
#ifndef HAVE_MAVE_H
#define HAVE_MAVE_H

#include "tmv.h"

struct mave;

struct mave *mave_create(int length);

void mave_destroy(struct mave *m);

tmv_t mave_accumulate(struct mave *m, tmv_t val);

void mave_reset(struct mave *m);

#endif
