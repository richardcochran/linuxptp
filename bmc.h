/**
 * @file bmc.h
 * @brief Best master clock algorithm
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
#ifndef HAVE_BMC_H
#define HAVE_BMC_H

#include "clock.h"
#include "port.h"
#include "fsm.h"

/**
 * BMC state decision algorithm.
 * @param c  The local clock.
 * @param r  The port in question.
 * @return   A @ref port_state value as the recommended state.
 */
enum port_state bmc_state_decision(struct clock *c, struct port *r);

/**
 * Compare two data sets.
 * @param a A dataset to compare.
 * @param b A dataset to compare.
 * @return An integer less than, equal to, or greater than zero
 *         if the dataset @a a is found, respectively, to be
 *         less than, to match, or be greater than @a b.
 */
int dscmp(struct dataset *a, struct dataset *b);

#endif
