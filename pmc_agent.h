/**
 * @file pmc_agent.h
 * @brief Client code for making PTP management requests.
 * @note Copyright (C) 2013 Miroslav Lichvar <mlichvar@redhat.com>
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
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

#ifndef HAVE_PMC_AGENT_H
#define HAVE_PMC_AGENT_H

#include "pmc_common.h"

struct pmc_node;

typedef int pmc_node_recv_subscribed_t(struct pmc_node *node,
				       struct ptp_message *msg,
				       int excluded);

struct pmc_node {
	struct pmc *pmc;
	int pmc_ds_requested;
	uint64_t pmc_last_update;
	int sync_offset;
	int leap;
	int utc_offset_traceable;
	int clock_identity_set;
	struct ClockIdentity clock_identity;
	pmc_node_recv_subscribed_t *recv_subscribed;
};

int init_pmc_node(struct config *cfg, struct pmc_node *node, const char *uds,
		  pmc_node_recv_subscribed_t *recv_subscribed);
void close_pmc_node(struct pmc_node *node);
int update_pmc_node(struct pmc_node *node, int subscribe);
int run_pmc_subscribe(struct pmc_node *node, int timeout);
int run_pmc_clock_identity(struct pmc_node *node, int timeout);
int run_pmc_wait_sync(struct pmc_node *node, int timeout);
int run_pmc_get_number_ports(struct pmc_node *node, int timeout);
void run_pmc_events(struct pmc_node *node);
int run_pmc_port_properties(struct pmc_node *node, int timeout,
			    unsigned int port, int *state,
			    int *tstamping, char *iface);
int run_pmc_get_utc_offset(struct pmc_node *node, int timeout);
int get_mgt_id(struct ptp_message *msg);
void *get_mgt_data(struct ptp_message *msg);

#endif

