/**
 * @file snmp4lptp.c
 * @brief Implements SNMP sub agent program for linuxptp
 * @note Copyright (C) 2018 Anders Selhammer <anders.selhammer@est.tech>
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
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "util.h"

static int open_snmp()
{
	snmp_enable_calllog();
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
			       NETSNMP_DS_AGENT_ROLE, 1);
	init_agent("linuxptpAgent");

	init_snmp("linuxptpAgent");

	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0;

	if (handle_term_signals()) {
		return -1;
	}

	if (open_snmp()) {
		return -1;
	}

	while (is_running()) {
		agent_check_and_process(1);
	}

	snmp_shutdown("linuxptpAgent");

	return err;
}
