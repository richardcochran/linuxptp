/**
 * @file unicast_service.h
 * @brief Unicast service
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
#ifndef HAVE_UNICAST_SERVICE_H
#define HAVE_UNICAST_SERVICE_H

struct port;
struct ptp_message;
struct tlv_extra;

#define SERVICE_GRANTED   0
#define SERVICE_DENIED    1
#define SERVICE_DISABLED  2

/**
 * Handle a request for unicast service.
 * @param p      The port on which the signaling message was received.
 * @param m      The signaling message containing the request.
 * @param extra  The TLV containing the request.
 * @return       SERVICE_GRANTED, SERVICE_DENIED, or SERVICE_DISABLED.
 */
int unicast_service_add(struct port *p, struct ptp_message *m,
			struct tlv_extra *extra);

/**
 * Frees all of the resources associated with a port's unicast service.
 * @param p      The port in question.
 */
void unicast_service_cleanup(struct port *p);

/**
 * Responds to a unicast service request with a denial.
 * @param p      The port on which the signaling message was received.
 * @param m      The signaling message containing the request.
 * @param extra  The TLV containing the request.
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_service_deny(struct port *p, struct ptp_message *m,
			 struct tlv_extra *extra);

/**
 * Responds to a unicast service request with a grant.
 * @param p      The port on which the signaling message was received.
 * @param m      The signaling message containing the request.
 * @param extra  The TLV containing the request.
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_service_grant(struct port *p, struct ptp_message *m,
			  struct tlv_extra *extra);

/**
 * Initializes unicast service on a given port.
 * @param p      The port in question.
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_service_initialize(struct port *p);

/**
 * Handle a unicast service cancellation.
 * @param p      The port on which the signaling message was received.
 * @param m      The signaling message containing the cancellation.
 * @param extra  The TLV containing the cancellation.
 */
void unicast_service_remove(struct port *p, struct ptp_message *m,
			    struct tlv_extra *extra);

/**
 * Handles the unicast service timer, sending messages according to schedule.
 * @param p      The port in question.
 * @return       Zero on success, non-zero otherwise.
 */
int unicast_service_timer(struct port *p);

#endif
