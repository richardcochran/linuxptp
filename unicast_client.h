/**
 * @file unicast_client.h
 * @brief Unicast client implementation
 * @note Copyright (C) 2018 Richard Cochran <richardcochran@gmail.com>
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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA.
 */
#ifndef HAVE_UNICAST_CLIENT_H
#define HAVE_UNICAST_CLIENT_H

#define UNICAST_CANCEL_ALL  (1 << ANNOUNCE | 1 << SYNC | 1 << DELAY_RESP)
#define UNICAST_CANCEL_SYDY (1 << SYNC | 1 << DELAY_RESP)

/**
 * Handles a CANCEL_UNICAST_TRANSMISSION TLV from the grantor.
 * @param p      The port on which the signaling message was received.
 * @param m      The signaling message containing the cancellation.
 * @param extra  The TLV containing the cancellation.
 * @return       Zero on success, or non-zero
 *               if transmission of the ACK message failed.
 */
int unicast_client_cancel(struct port *p, struct ptp_message *m,
			  struct tlv_extra *extra);

/**
 * Finds and initializes the unicast master table configured for this
 * port, if any.
 * @param port   The port in question.
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_client_initialize(struct port *port);

/**
 * Frees all of the resources associated with a port's unicast client.
 * @param p      The port in question.
 */
void unicast_client_cleanup(struct port *p);

/**
 * Tests whether a unicast master table is associated with a given port.
 * @param p      The port in question.
 * @return       One (1) if a unicast master table is configured on the port,
 *               or zero otherwise.
 */
int unicast_client_enabled(struct port *p);

/**
 * Handles a GRANT_UNICAST_TRANSMISSION TLV from the grantor.
 * @param p      The port on which the signaling message was received.
 * @param m      The signaling message containing the grant.
 * @param extra  The TLV containing the grant.
 */
void unicast_client_grant(struct port *p, struct ptp_message *m,
			  struct tlv_extra *extra);

/**
 * Programs the unicast request timer.
 * @param p      The port in question.
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_client_set_tmo(struct port *p);

/**
 * Notifies the unicast client code that the port state has changed.
 * @param p      The port in question.
 */
void unicast_client_state_changed(struct port *p);

/**
 * Handles the unicast request timer, sending requests as needed.
 * @param p      The port in question.
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_client_timer(struct port *p);

/**
 * Check whether a message was received from an entry in the unicast
 * master table.
 * @param p      The port in question.
 * @param m      The message in question.
 * @return       One (1) if the message is from an entry in the unicast
 *               master table, or zero otherwise.
 */
int unicast_client_msg_is_from_master_table_entry(struct port *p,
						  struct ptp_message *m);

/**
 * Transmit CANCEL_UNICAST_TRANSMISSION TLV to destination address.
 * @param p        The port in question.
 * @param dst      The destination address.
 * @param bitmask  Cancel message type bitmask
 * @param
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_client_tx_cancel(struct port *p,
			     struct unicast_master_address *dst,
			     unsigned int bitmask);
#endif
