/**
 * @file telecom.c
 * @note Copyright (C) 2017 Richard Cochran <richardcochran@gmail.com>
 *
 * Derived from code in bmc.c.
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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA.
 */
#include <string.h>

#include "bmc.h"
#include "ds.h"

int telecom_dscmp(struct dataset *a, struct dataset *b)
{
	int diff;

	if (a == b)
		return 0;
	if (a && !b)
		return A_BETTER;
	if (b && !a)
		return B_BETTER;

	if (a->quality.clockClass < b->quality.clockClass)
		return A_BETTER;
	if (a->quality.clockClass > b->quality.clockClass)
		return B_BETTER;

	if (a->quality.clockAccuracy < b->quality.clockAccuracy)
		return A_BETTER;
	if (a->quality.clockAccuracy > b->quality.clockAccuracy)
		return B_BETTER;

	if (a->quality.offsetScaledLogVariance <
	    b->quality.offsetScaledLogVariance)
		return A_BETTER;
	if (a->quality.offsetScaledLogVariance >
	    b->quality.offsetScaledLogVariance)
		return B_BETTER;

	if (a->priority2 < b->priority2)
		return A_BETTER;
	if (a->priority2 > b->priority2)
		return B_BETTER;

	if (a->localPriority < b->localPriority)
		return A_BETTER;
	if (a->localPriority > b->localPriority)
		return B_BETTER;

	if (a->quality.clockClass <= 127)
		return dscmp2(a, b);

	diff = memcmp(&a->identity, &b->identity, sizeof(a->identity));

	if (!diff)
		return dscmp2(a, b);

	return diff < 0 ? A_BETTER : B_BETTER;
}
