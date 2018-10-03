/**
 * @file as_capable.h
 * @brief Enumerates the states for asCapable.
 * @note Copyright (C) 2018 Intel Corporation
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
#ifndef HAVE_AS_CAPABLE_H
#define HAVE_AS_CAPABLE_H

/* Enum used by the asCapable config option. */
enum as_capable_option {
	AS_CAPABLE_TRUE,
	AS_CAPABLE_AUTO,
};

/*
 * Defines whether the device can interoperate with the device on other end via
 * IEEE 802.1AS protocol.
 *
 * More information about this in Section 10.2.4.1 of IEEE 802.1AS standard.
 */
enum as_capable {
	NOT_CAPABLE,
	AS_CAPABLE,
	/*
	 * Non-standard extension to support Automotive Profile. asCapable
	 * always set to true without checking the system at other end.
	 */
	ALWAYS_CAPABLE,
};

#endif
