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

#define A_BETTER_TOPO  2
#define A_BETTER       1
#define B_BETTER      -1
#define B_BETTER_TOPO -2

enum {
	DS_CMP_IEEE1588,
	DS_CMP_G8275,
};

/**
 * BMC state decision algorithm.
 * @param c  The local clock.
 * @param r  The port in question.
 * @param compare  The data set comparison algorithm.
 * @return   A @ref port_state value as the recommended state.
 */
enum port_state bmc_state_decision(struct clock *c, struct port *r,
				   int (*comapre)(struct dataset *a, struct dataset *b));

/**
 * Compare two data sets using the algorithm defined in IEEE 1588.
 * @param a A dataset to compare.
 * @param b A dataset to compare.
 * @return An integer less than, equal to, or greater than zero
 *         if the dataset @a a is found, respectively, to be
 *         less than, to match, or be greater than @a b.
 */
int dscmp(struct dataset *a, struct dataset *b);

/**
 * Second part of the data set comparison algorithm, not for general
 * public use.
 */
int dscmp2(struct dataset *a, struct dataset *b);

/**
 * Compare two data sets using the algorithm defined in the Telecom
 * Profiles according to ITU-T G.8275.1 and G.8275.2.
 *
 * @param a A dataset to compare.
 * @param b A dataset to compare.
 * @return An integer less than, equal to, or greater than zero
 *         if the dataset @a a is found, respectively, to be
 *         less than, to match, or be greater than @a b.
 */
int telecom_dscmp(struct dataset *a, struct dataset *b);

#endif
