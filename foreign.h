/**
 * @file foreign.h
 * @brief Defines a foreign clock record.
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
#ifndef HAVE_FOREIGN_H
#define HAVE_FOREIGN_H

#include <sys/queue.h>

#include "ds.h"
#include "port.h"

#define FOREIGN_MASTER_THRESHOLD 2

struct foreign_clock {
	/**
	 * Pointer to next foreign_clock in list.
	 */
	LIST_ENTRY(foreign_clock) list;

	/**
	 * A list of received announce messages.
	 *
	 * The data set field, foreignMasterPortIdentity, is the
	 * sourcePortIdentity of the first message.
	 */
	TAILQ_HEAD(messages, ptp_message) messages;

	/**
	 * Number of elements in the message list,
	 * aka foreignMasterAnnounceMessages.
	 */
	unsigned int n_messages;

	/**
	 * Pointer to the associated port.
	 */
	struct port *port;

	/**
	 * Contains the information from the latest announce message
	 * in a form suitable for comparision in the BMCA.
	 */
	struct dataset dataset;
};

#endif
