/**
 * @file fault.h
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
#include <stdint.h>

enum fault_type {
	FT_UNSPECIFIED = 0,
	FT_BAD_PEER_NETWORK,
	FT_SWITCH_PHC,
	FT_CNT,
};

enum fault_tmo_type {
	FTMO_LINEAR_SECONDS = 0,
	FTMO_LOG2_SECONDS,
	FTMO_CNT,
};

struct fault_interval {
	enum fault_tmo_type type;
	int32_t val;
};

const char *ft_str(enum fault_type ft);
