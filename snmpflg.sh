#!/bin/sh
#
# Discover the SNMP CFLAGS to use during compilation.
#
# Copyright (C) 2018 Anders Selhammer <anders.selhammer@est.tech>
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
# Look for libsnmp presence.  When cross compiling, the user will
# specify the include path in EXTRA_CFLAGS.
#
snmp_flags()
{
	# Get list of directories searched for header files.
	dirs=$(echo "" | ${CROSS_COMPILE}cpp ${EXTRA_CFLAGS} -Wp,-v 2>&1 >/dev/null | grep ^" /")

	# Look for libsnmp presence
	for d in $dirs; do
		files=$(find $d -type f -name net-snmp-agent-includes.h)
		for f in $files; do
			if grep -q NET_SNMP_AGENT_INCLUDES_H $f; then
				printf " -DHAVE_NET_SNMP `net-snmp-config --cflags`"
				break 2
			fi
		done
	done
}

echo "$(snmp_flags)"
