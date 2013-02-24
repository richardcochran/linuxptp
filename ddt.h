/**
 * @file ddt.h
 * @brief Derived data types
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
#ifndef HAVE_DDT_H
#define HAVE_DDT_H

#include "pdt.h"

#define PACKED __attribute__((packed))

typedef Integer64 TimeInterval; /* nanoseconds << 16 */

/** On the wire time stamp format. */
struct Timestamp {
	uint16_t   seconds_msb; /* 16 bits + */
	uint32_t   seconds_lsb; /* 32 bits = 48 bits*/
	UInteger32 nanoseconds;
} PACKED;

/** Internal binary time stamp format. */
struct timestamp {
	uint64_t   sec;
	UInteger32 nsec;
};

struct ClockIdentity {
	Octet id[8];
};

struct PortIdentity {
	struct ClockIdentity clockIdentity;
	UInteger16           portNumber;
} PACKED;

struct PortAddress {
	Enumeration16 networkProtocol;
	UInteger16    addressLength;
	Octet         address[0];
} PACKED;

struct PhysicalAddress {
	UInteger16 length;
	Octet      address[0];
} PACKED;

struct ClockQuality {
	UInteger8     clockClass;
	Enumeration8  clockAccuracy;
	UInteger16    offsetScaledLogVariance;
} PACKED;

struct TLV {
	Enumeration16 type;
	UInteger16    length; /* must be even */
	Octet         value[0];
} PACKED;

struct PTPText {
	UInteger8 length;
	Octet     text[0];
} PACKED;

/* A static_ptp_text is like a PTPText but includes space to store the
 * text inside the struct. The text array must always be
 * null-terminated. Also tracks a maximum number of symbols. Note in
 * UTF-8, # symbols != # bytes.
 */
#define MAX_PTP_OCTETS 255
struct static_ptp_text {
	/* null-terminated array of UTF-8 symbols */
	Octet text[MAX_PTP_OCTETS + 1];
	/* number of used bytes in text, not including trailing null */
	int length;
	/* max number of UTF-8 symbols that can be in text */
	int max_symbols;
};

struct FaultRecord {
	UInteger16       faultRecordLength;
	struct Timestamp faultTime;
	Enumeration8     severityCode;
	struct PTPText   faultName;
	struct PTPText   faultValue;
	struct PTPText   faultDescription;
};

#endif
