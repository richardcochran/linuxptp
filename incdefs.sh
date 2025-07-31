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
	dirs=$(${CC} -E -Wp,-v -xc /dev/null 2>&1 >/dev/null | grep ^" /")

	# Look for clock_adjtime().
	for d in $dirs; do
		files=$(find $d -type f -name time.h -o -name timex.h)
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

	# Look for nettle support.
	for d in $dirs; do
		sdirs=$(find $d -type d -name "nettle")
		for s in $sdirs; do
			have_hmac="0"
			files=$(find $s -type f -name hmac.h)
			for f in $files; do
				if grep -q hmac_sha256_set_key $f; then
					have_hmac="1"
					break 1;
				fi
			done
			have_memops="0"
			files=$(find $s -type f -name memops.h)
			for f in $files; do
				if grep -q memeql_sec $f; then
					have_memops="1"
					break 1;
				fi
			done
			have_nettle_meta="0"
			files=$(find $s -type f -name nettle-meta.h)
			for f in $files; do
				if grep -q nettle_get_macs $f; then
					have_nettle_meta="1"
					break 1;
				fi
			done
			if [ $have_hmac = "1" ] &&
			   [ $have_memops = "1" ] &&
			   [ $have_nettle_meta = "1" ]; then
				printf " -DHAVE_NETTLE"
				break 2
			fi
		done
	done

	# Look for gnutls support.
	for d in $dirs; do
		sdirs=$(find $d -type d -name "gnutls")
		for s in $sdirs; do
			files=$(find $s -type f -name crypto.h)
			for f in $files; do
				if grep -q gnutls_hmac_init $f; then
					printf " -DHAVE_GNUTLS"
					break 3
				fi
			done
		done
	done

	# Look for gnupg support.
	for d in $dirs; do
		files=$(find $d -type f -name gcrypt.h)
		for f in $files; do
			if grep -q gcry_mac_open $f; then
				printf " -DHAVE_GNUPG"
				break 2
			fi
		done
	done

	# Look for openssl support.
	for d in $dirs; do
		sdirs=$(find $d -type d -name "openssl")
		for s in $sdirs; do
			have_crypto="0"
			files=$(find $s -type f -name crypto.h)
			for f in $files; do
				if grep -q CRYPTO_memcmp $f; then
					have_crypto="1"
					break 1;
				fi
			done
			have_evp="0"
			files=$(find $s -type f -name evp.h)
			for f in $files; do
				if grep -q EVP_MAC_init $f; then
					have_evp="1"
					break 1;
				fi
			done
			if [ $have_crypto = "1" ] &&
			   [ $have_evp = "1" ]; then
				printf " -DHAVE_OPENSSL"
				break 2
			fi
		done
	done

	# Look for libcap support.
	for d in $dirs; do
		if test -e $d/sys/capability.h; then
			printf " -DHAVE_LIBCAP"
			break
		fi
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
	ptp_clock=/usr/include/linux/ptp_clock.h
	if_team=/usr/include/linux/if_team.h

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

	if grep -q HWTSTAMP_TX_ONESTEP_P2P ${prefix}${tstamp}; then
		printf " -DHAVE_ONESTEP_P2P"
	fi

	if grep -q SOF_TIMESTAMPING_BIND_PHC ${prefix}${tstamp}; then
		printf " -DHAVE_VCLOCKS"
	fi

	if grep -q adjust_phase ${prefix}${ptp_clock}; then
		printf " -DHAVE_PTP_CAPS_ADJUST_PHASE"
	fi

	if grep -q -s TEAM_GENL_NAME ${prefix}${if_team}; then
		printf " -DHAVE_IF_TEAM"
	fi
}

flags="$(user_flags)$(kernel_flags)"
echo "$flags"
