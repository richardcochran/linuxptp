/**
 * @file notification.h
 * @brief Definitions for the notification framework.
 * @note Copyright (C) 2014 Red Hat, Inc., Jiri Benc <jbenc@redhat.com>
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
#ifndef HAVE_NOTIFICATION_H
#define HAVE_NOTIFICATION_H

#include <stdbool.h>
#include <stdint.h>

static inline void event_bitmask_set(uint8_t *bitmask, unsigned int event,
				     bool value)
{
	unsigned int event_pos = event / 8;
	uint8_t event_bit = 1 << (event % 8);

	if (value) {
		bitmask[event_pos] |= event_bit;
	} else {
		bitmask[event_pos] &= ~(event_bit);
	}
}

static inline bool event_bitmask_get(uint8_t *bitmask, unsigned int event)
{
	return (bitmask[event / 8] & (1 << (event % 8))) ? true : false;
}

enum notification {
	NOTIFY_PORT_STATE,
	NOTIFY_TIME_SYNC,
};

#endif
