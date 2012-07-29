/**
 * @file tlv.h
 * @brief Implements helper routines for processing Type Length Value fields.
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
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
#ifndef HAVE_TLV_H
#define HAVE_TLV_H

#include "ddt.h"

/**
 * Converts recognized value sub-fields into host byte order.
 * @param tlv Pointer to a Type Length Value field.
 */
void tlv_post_recv(struct TLV *tlv);

/**
 * Converts recognized value sub-fields into network byte order.
 * @param tlv Pointer to a Type Length Value field.
 */
void tlv_pre_send(struct TLV *tlv);

#endif
