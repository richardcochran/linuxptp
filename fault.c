/**
 * @file fault.c
 * @note Copyright (C) 2013 Delio Brignoli <dbrignoli@audioscience.com>
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
#include "fault.h"

static const char *fault_type_str[FT_CNT] = {
	"FT_UNSPECIFIED",
	"FT_BAD_PEER_NETWORK",
};

const char *ft_str(enum fault_type ft)
{
	if (ft < 0 || ft >= FT_CNT)
		return "INVALID_FAULT_TYPE_ENUM";
	return fault_type_str[ft];
}
