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

#include "dm.h"
#include "fd.h"
#include "foreign.h"
#include "fsm.h"
#include "transport.h"

/* forward declarations */
struct interface;
struct clock;

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
 * Forward a message on a given port.
 * @param port    A pointer previously obtained via port_open().
 * @param msg     The message to send. Must be in network byte order.
 * @param msglen  The length of the message in bytes.
 * @return        Zero on success, non-zero otherwise.
 */
int port_forward(struct port *p, struct ptp_message *msg, int msglen);

/**
 * Obtain a port's identity.
 * @param p        A pointer previously obtained via port_open().
 * @return         The port identity of 'p'.
 */
struct PortIdentity port_identity(struct port *p);

/**
 * Manage a port according to a given message.
 * @param p        A pointer previously obtained via port_open().
 * @param ingress  The port on which 'msg' was received.
 * @param msg      A management message.
 * @return         Zero if the message is valid, non-zero otherwise.
 */
int port_manage(struct port *p, struct port *ingress, struct ptp_message *msg);

/**
 * Send a management error status message.
 * @param pid       The id of the responding port.
 * @param ingress   Port on which the 'req' was received.
 * @param req       The management message which triggered the error.
 * @param error_id  One of the management error ID values.
 * @return          Zero on success, non-zero otherwise.
 */
int port_managment_error(struct PortIdentity pid, struct port *ingress,
			 struct ptp_message *req, Enumeration16 error_id);

/**
 * Allocate a reply to a management message.
 *
 * Messages are reference counted, and newly allocated messages have a
 * reference count of one. Allocated messages are freed using the
 * function @ref msg_put().
 *
 * @param pid      The id of the responding port.
 * @param ingress  The port on which 'req' was received.
 * @param req      A management message.
 * @return         Pointer to a message on success, NULL otherwise.
 */
struct ptp_message *port_management_reply(struct PortIdentity pid,
					  struct port *ingress,
					  struct ptp_message *req);

/**
 * Open a network port.
 * @param phc_index     The PHC device index for the network device.
 * @param timestamping  The timestamping mode for this port.
 * @param number	An arbitrary number assigned to this port.
 * @param interface     The interface data
 * @param clock         A pointer to the system PTP clock.
 * @return A pointer to an open port on success, or NULL otherwise.
 */
struct port *port_open(int phc_index,
		       enum timestamp_type timestamping,
		       int number,
		       struct interface *interface,
		       struct clock *clock);

/**
 * Returns a port's current state.
 * @param port  A port instance.
 * @return      One of the @ref port_state values.
 */
enum port_state port_state(struct port *port);

#endif
