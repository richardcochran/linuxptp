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

/** Opaque type. */
struct port;

/**
 * Returns the dataset from a port's best foreign clock record, if any
 * has yet been discovered.
 *
 * @param port  A port instance.
 * @return      A pointer to a dataset, or NULL.
 */
struct dataset *port_best_foreign(struct port *port);

/**
 * Returns a port's current state.
 * @param port  A port instance.
 * @return      One of the @ref port_state values.
 */
enum port_state port_state(struct port *port);

#endif
