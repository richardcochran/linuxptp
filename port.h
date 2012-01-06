/**
 * @file port.h
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
#ifndef HAVE_PORT_H
#define HAVE_PORT_H

#include "fd.h"
#include "foreign.h"
#include "fsm.h"
#include "transport.h"

/** Defines the possible delay mechanisms. */
enum delay_mechanism {
	DM_AUTO, /**< Just go with the flow  */
	DM_E2E,  /**< End to End mechanism   */
	DM_P2P,  /**< Peer to Peer mechanism */
};

/** Opaque type. */
struct port;

/**
 * Returns the dataset from a port's best foreign clock record, if any
 * has yet been discovered. This function does not bring the returned
 * dataset up to date, so the caller should invoke port_compute_best()
 * beforehand.
 *
 * @param port  A pointer previously obtained via port_open().
 * @return      A pointer to a dataset, or NULL.
 */
struct dataset *port_best_foreign(struct port *port);

/**
 * Close a port and free its associated resources. After this call
 * returns, @a port is no longer a valid port instance.
 *
 * @param port A pointer previously obtained via port_open().
 */
void port_close(struct port *port);

/**
 * Computes the 'best' foreign master discovered on a port. This has
 * the side effect of updating the 'dataset' field of the returned
 * foreign master.
 *
 * @param port A pointer previously obtained via port_open().
 * @return A pointer to the port's best foreign master, or NULL.
 */
struct foreign_clock *port_compute_best(struct port *port);

/**
 * Dispatch a port event. This may cause a state transition on the
 * port, with the associated side effect.
 *
 * @param port A pointer previously obtained via port_open().
 * @param event One of the @a fsm_event codes.
 * @param mdiff Whether a new master has been selected.
 */
void port_dispatch(struct port *p, enum fsm_event event, int mdiff);

/**
 * Generates state machine events based on activity on a port's file
 * descriptors.
 *
 * @param port A pointer previously obtained via port_open().
 * @param fd_index The index of the active file descriptor.
 * @return One of the @a fsm_event codes.
 */
enum fsm_event port_event(struct port *port, int fd_index);

/**
 * Open a network port.
 * @param pod           A pointer to a default port data set for this port.
 * @param name          The name of the network interface.
 * @param transport     The network transport type to use on this port.
 * @param timestamping  The flavor of time stamping to use on this port.
 * @param number        An arbitrary port number for this port.
 * @param dm            Which delay mechanism to use on this port.
 * @param clock         A pointer to the system PTP clock.
 * @return A pointer to an open port on success, or NULL otherwise.
 */
struct port *port_open(struct port_defaults *pod,
		       char *name,
		       enum transport_type transport,
		       enum timestamp_type timestamping,
		       int number,
		       enum delay_mechanism dm,
		       struct clock *clock);

/**
 * Returns a port's current state.
 * @param port  A port instance.
 * @return      One of the @ref port_state values.
 */
enum port_state port_state(struct port *port);

#endif
