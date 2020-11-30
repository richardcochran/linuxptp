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

#include <stdbool.h>

#include "pmc_common.h"

struct pmc_agent;

typedef int pmc_node_recv_subscribed_t(void *context, struct ptp_message *msg,
				       int excluded);

int init_pmc_node(struct config *cfg, struct pmc_agent *agent, const char *uds,
		  pmc_node_recv_subscribed_t *recv_subscribed, void *context);
int run_pmc_wait_sync(struct pmc_agent *agent, int timeout);

/**
 * Creates an instance of a PMC agent.
 * @return  Pointer to a PMC instance on success, NULL otherwise.
 */
struct pmc_agent *pmc_agent_create(void);

/**
 * Destroys an instance of a PMC agent.
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 */
void pmc_agent_destroy(struct pmc_agent *agent);

/**
 * Disconnects the PMC agent from the ptp4l service.
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 */
void pmc_agent_disable(struct pmc_agent *agent);

/**
 * Gets the current leap adjustment.
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @return       The leap adjustment in seconds, either 1, 0, or -1.
 */
int pmc_agent_get_leap(struct pmc_agent *agent);

/**
 * Gets the number of local ports from the default data set.  Users
 * should first call pmc_agent_query_dds() before invoking this
 * function.
 *
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @return       The non-negative number of ports, or -1 if unknown.
 */
int pmc_agent_get_number_ports(struct pmc_agent *agent);

/**
 * Gets the TAI-UTC offset.
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @return       Current offset in seconds.
 */
int pmc_agent_get_sync_offset(struct pmc_agent *agent);

/**
 * Queries the local clock's default data set from the ptp4l service.
 * The result of the query will be cached inside of the agent.
 *
 * In addition:
 *
 * - The port state notification callback might be invoked.
 *
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @param timeout  Transmit and receive timeout in milliseconds.
 * @return         Zero on success, negative error code otherwise.
 */
int pmc_agent_query_dds(struct pmc_agent *agent, int timeout);

/**
 * Queries the port properties of a given port from the ptp4l service.
 *
 * In addition:
 *
 * - The port state notification callback might be invoked.
 *
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @param timeout    Transmit and receive timeout in milliseconds.
 * @param port       The port index of interest.
 * @param state      Buffer to hold the returned port state.
 * @param tstamping  Buffer to hold the returned time stamping flavor.
 * @param iface      Buffer to hold the returned interface name.
 * @return           Zero on success, negative error code otherwise.
 */
int pmc_agent_query_port_properties(struct pmc_agent *agent, int timeout,
				    unsigned int port, int *state,
				    int *tstamping, char *iface);

/**
 * Queries the TAI-UTC offset and the current leap adjustment from the
 * ptp4l service.
 *
 * In addition:
 *
 * - The port state notification callback might be invoked.
 *
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @param timeout  Transmit and receive timeout in milliseconds.
 * @return         Zero on success, negative error code otherwise.
 */
int pmc_agent_query_utc_offset(struct pmc_agent *agent, int timeout);

/**
 * Sets the TAI-UTC offset.
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @param offset Desired offset in seconds.
 */
void pmc_agent_set_sync_offset(struct pmc_agent *agent, int offset);

/**
 * Subscribes to push notifications of changes in port state.
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @param timeout  Transmit and receive timeout in milliseconds.
 * @return         Zero on success, negative error code otherwise.
 */
int pmc_agent_subscribe(struct pmc_agent *agent, int timeout);

/**
 * Polls for push notifications from the local ptp4l service.
 *
 * In addition:
 *
 * - Queries the local ptp4l instance to update the TAI-UTC offset and
 *   the current leap second flags.
 * - Any active port state subscription will be renewed.
 * - The port state notification callback might be invoked.
 *
 * This function should be called periodically at least once per
 * minute to keep both the port state and the leap second flags up to
 * date.  Note that the PMC agent rate limits the query to once per
 * minute, and so the caller may safely invoke this method more often
 * than that.
 *
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @return       Zero on success, negative error code otherwise.
 */
int pmc_agent_update(struct pmc_agent *agent);

/**
 * Tests whether the current UTC offset is traceable.
 * @param agent  Pointer to a PMC instance obtained via @ref pmc_agent_create().
 * @return       True is the offset is traceable, false otherwise.
 */
bool pmc_agent_utc_offset_traceable(struct pmc_agent *agent);

#endif
