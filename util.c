/**
 * @file util.c
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

#include "sk.h"
#include "util.h"

char *ps_str[] = {
	"NONE",
	"INITIALIZING",
	"FAULTY",
	"DISABLED",
	"LISTENING",
	"PRE_MASTER",
	"MASTER",
	"GRAND_MASTER",
	"PASSIVE",
	"UNCALIBRATED",
	"SLAVE",
};

char *ev_str[] = {
	"NONE",
	"POWERUP",
	"INITIALIZE",
	"DESIGNATED_ENABLED",
	"DESIGNATED_DISABLED",
	"FAULT_CLEARED",
	"FAULT_DETECTED",
	"STATE_DECISION_EVENT",
	"QUALIFICATION_TIMEOUT_EXPIRES",
	"ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES",
	"SYNCHRONIZATION_FAULT",
	"MASTER_CLOCK_SELECTED",
	"RS_MASTER",
	"RS_GRAND_MASTER",
	"RS_SLAVE",
	"RS_PASSIVE",
};

char *cid2str(struct ClockIdentity *id)
{
	static char buf[64];
	unsigned char *ptr = id->id;
	snprintf(buf, sizeof(buf), "%02x%02x%02x.%02x%02x.%02x%02x%02x",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7]);
	return buf;
}

char *pid2str(struct PortIdentity *id)
{
	static char buf[64];
	unsigned char *ptr = id->clockIdentity.id;
	snprintf(buf, sizeof(buf), "%02x%02x%02x.%02x%02x.%02x%02x%02x-%hu",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7],
		 id->portNumber);
	return buf;
}

int generate_clock_identity(struct ClockIdentity *ci, char *name)
{
	unsigned char mac[6];
	if (sk_interface_macaddr(name, mac, sizeof(mac)))
		return -1;
	ci->id[0] = mac[0];
	ci->id[1] = mac[1];
	ci->id[2] = mac[2];
	ci->id[3] = 0xFF;
	ci->id[4] = 0xFE;
	ci->id[5] = mac[3];
	ci->id[6] = mac[4];
	ci->id[7] = mac[5];
	return 0;
}
