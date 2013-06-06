/**
 * @file phc.c
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
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/ptp_clock.h>

#include "phc.h"

/*
 * On 32 bit platforms, the PHC driver's maximum adjustment (type
 * 'int' in units of ppb) can overflow the timex.freq field (type
 * 'long'). So in this case we clamp the maximum to the largest
 * possible adjustment that fits into a 32 bit long.
 */
#define BITS_PER_LONG	(sizeof(long)*8)
#define MAX_PPB_32	32767999	/* 2^31 - 1 / 65.536 */

static int phc_get_caps(clockid_t clkid, struct ptp_clock_caps *caps);

clockid_t phc_open(char *phc)
{
	clockid_t clkid;
	struct ptp_clock_caps caps;
	int fd = open(phc, O_RDWR);

	if (fd < 0)
		return CLOCK_INVALID;

	clkid = FD_TO_CLOCKID(fd);
	/* check if clkid is valid */
	if (phc_get_caps(clkid, &caps)) {
		close(fd);
		return CLOCK_INVALID;
	}

	return clkid;
}

void phc_close(clockid_t clkid)
{
	if (clkid == CLOCK_INVALID)
		return;

	close(CLOCKID_TO_FD(clkid));
}

static int phc_get_caps(clockid_t clkid, struct ptp_clock_caps *caps)
{
	int fd = CLOCKID_TO_FD(clkid), err;

	err = ioctl(fd, PTP_CLOCK_GETCAPS, caps);
	if (err)
		perror("PTP_CLOCK_GETCAPS");
	return err;
}

int phc_max_adj(clockid_t clkid)
{
	int max;
	struct ptp_clock_caps caps;

	if (phc_get_caps(clkid, &caps))
		return 0;

	max = caps.max_adj;

	if (BITS_PER_LONG == 32 && max > MAX_PPB_32)
		max = MAX_PPB_32;

	return max;
}

int phc_has_pps(clockid_t clkid)
{
	struct ptp_clock_caps caps;

	if (phc_get_caps(clkid, &caps))
		return 0;
	return caps.pps;
}
