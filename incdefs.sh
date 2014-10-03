#!/bin/sh
#
# Discover the CFLAGS to use during compilation.
#
# Copyright (C) 2013 Richard Cochran <richardcochran@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#
# Look for functional prototypes in the C library.
#
user_flags()
{
	# Needed for vasprintf().
	printf " -D_GNU_SOURCE"

	# Get list of directories searched for header files.
	dirs=$(echo "" | ${CROSS_COMPILE}cpp -Wp,-v 2>&1 >/dev/null | grep ^" /")

	# Look for clock_adjtime().
	for d in $dirs; do
		files=$(find $d -type f -name time.h)
		for f in $files; do
			if grep -q clock_adjtime $f; then
				printf " -DHAVE_CLOCK_ADJTIME"
				break 2
			fi
		done
	done

	# Look for posix_spawn().
	for d in $dirs; do
		files=$(find $d -type f -name spawn.h)
		for f in $files; do
			if grep -q posix_spawn $f; then
				printf " -DHAVE_POSIX_SPAWN"
				break 2
			fi
		done
	done
}

#
# Find the most appropriate kernel header for the SIOCSHWTSTAMP ioctl.
#
# 1. custom kernel or cross build using KBUILD_OUTPUT
# 2. sanitized headers installed under /lib/modules/`uname -r`/build
# 3. normal build using standard system headers
#
kernel_flags()
{
	prefix=""
	tstamp=/usr/include/linux/net_tstamp.h

	if [ "x$KBUILD_OUTPUT" != "x" ]; then
		# With KBUILD_OUTPUT set, we are building against
		# either a custom kernel or a cross compiled kernel.
		build=${KBUILD_OUTPUT}
	else
		# If the currently running kernel is a custom build
		# with the headers installed, then we should use them.
		build=/lib/modules/`uname -r`/build
	fi

	if [ -f ${build}${tstamp} ]; then
		prefix=${build}
		printf " -I%s/usr/include" $prefix
	fi

	if grep -q HWTSTAMP_TX_ONESTEP_SYNC ${prefix}${tstamp}; then
		printf " -DHAVE_ONESTEP_SYNC"
	fi
}

flags="$(user_flags)$(kernel_flags)"
echo "$flags"
