/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef HAVE_DPDK_GLUE_H
#define HAVE_DPDK_GLUE_H

#include "address.h"
#include "msg.h"
#include "transport.h"

int ptp_dpdk_open(const char *ifname, enum timestamp_type tt, int *poll_fd);
int ptp_dpdk_close(void);
int ptp_dpdk_recv(void *buf, int buflen, struct address *addr,
		  struct hw_timestamp *hwts);
int ptp_dpdk_send(enum transport_event event, int peer, void *buf,
		  int buflen, struct address *addr,
		  struct hw_timestamp *hwts);
int ptp_dpdk_physical_addr(uint8_t *addr);
int ptp_dpdk_protocol_addr(uint8_t *addr);

#endif
