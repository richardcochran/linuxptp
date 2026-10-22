/**
 * @file fine_ts.c
 * @brief Optional provider of sub-nanosecond time stamp corrections.
 * @note Copyright (C) 2026 Liquid Instruments Pty Ltd
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
#include <string.h>

#include "fine_ts.h"
#include "provider.h"

static struct provider fine_ts = {
	.name = "fine time stamp provider",
	.fallback = "using the kernel time stamp unchanged",
	.magic = FINE_TS_MAGIC,
	.version = FINE_TS_VERSION,
	.fd = -1,
};

int fine_ts_init(struct config *cfg)
{
	return provider_open(&fine_ts, cfg, "fine_ts_provider",
			     "fine_ts_timeout");
}

void fine_ts_cleanup(void)
{
	provider_close(&fine_ts);
}

void fine_ts_apply(unsigned int ifindex, enum fine_ts_direction dir,
		   uint8_t msg_type, uint16_t seqid,
		   const struct PortIdentity *pid, tmv_t *ts)
{
	struct fine_ts_request req;
	struct fine_ts_reply rep;
	int64_t nanoseconds;

	if (fine_ts.fd < 0) {
		return;
	}

	nanoseconds = tmv_to_nanoseconds(*ts);

	memset(&req, 0, sizeof(req));
	req.magic = FINE_TS_MAGIC;
	req.version = FINE_TS_VERSION;
	req.direction = dir;
	req.message_type = msg_type;
	req.ifindex = ifindex;
	req.sequence_id = seqid;
	req.port_identity = *pid;
	req.seconds = nanoseconds / NS_PER_SEC;
	req.nanoseconds = nanoseconds % NS_PER_SEC;
	req.xid = ++fine_ts.xid;

	if (provider_exchange(&fine_ts, &req, sizeof(req), req.xid,
			      &rep, sizeof(rep))) {
		return;
	}
	fine_ts.failures = 0;
	if (rep.status == FINE_TS_OK) {
		*ts = tmv_add(*ts, tmv_normalize(0, rep.fraction));
	}
}
