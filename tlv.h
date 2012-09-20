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
#include "msg.h"

/* TLV types */
#define TLV_MANAGEMENT					0x0001
#define TLV_MANAGEMENT_ERROR_STATUS			0x0002
#define TLV_ORGANIZATION_EXTENSION			0x0003
#define TLV_REQUEST_UNICAST_TRANSMISSION		0x0004
#define TLV_GRANT_UNICAST_TRANSMISSION			0x0005
#define TLV_CANCEL_UNICAST_TRANSMISSION			0x0006
#define TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION	0x0007
#define TLV_PATH_TRACE					0x0008
#define TLV_ALTERNATE_TIME_OFFSET_INDICATOR		0x0009
#define TLV_AUTHENTICATION				0x2000
#define TLV_AUTHENTICATION_CHALLENGE			0x2001
#define TLV_SECURITY_ASSOCIATION_UPDATE			0x2002
#define TLV_CUM_FREQ_SCALE_FACTOR_OFFSET		0x2003

enum management_action {
	GET,
	SET,
	RESPONSE,
	COMMAND,
	ACKNOWLEDGE,
};

/* Clock management ID values */
#define USER_DESCRIPTION				0x0002
#define SAVE_IN_NON_VOLATILE_STORAGE			0x0003
#define RESET_NON_VOLATILE_STORAGE			0x0004
#define INITIALIZE					0x0005
#define FAULT_LOG					0x0006
#define FAULT_LOG_RESET					0x0007
#define DEFAULT_DATA_SET				0x2000
#define CURRENT_DATA_SET				0x2001
#define PARENT_DATA_SET					0x2002
#define TIME_PROPERTIES_DATA_SET			0x2003
#define PRIORITY1					0x2005
#define PRIORITY2					0x2006
#define DOMAIN						0x2007
#define SLAVE_ONLY					0x2008
#define TIME						0x200F
#define CLOCK_ACCURACY					0x2010
#define UTC_PROPERTIES					0x2011
#define TRACEABILITY_PROPERTIES				0x2012
#define TIMESCALE_PROPERTIES				0x2013
#define PATH_TRACE_LIST					0x2015
#define PATH_TRACE_ENABLE				0x2016
#define GRANDMASTER_CLUSTER_TABLE			0x2017
#define ACCEPTABLE_MASTER_TABLE				0x201A
#define ACCEPTABLE_MASTER_MAX_TABLE_SIZE		0x201C
#define ALTERNATE_TIME_OFFSET_ENABLE			0x201E
#define ALTERNATE_TIME_OFFSET_NAME			0x201F
#define ALTERNATE_TIME_OFFSET_MAX_KEY			0x2020
#define ALTERNATE_TIME_OFFSET_PROPERTIES		0x2021
#define TRANSPARENT_CLOCK_DEFAULT_DATA_SET		0x4000
#define PRIMARY_DOMAIN					0x4002
#define TIME_STATUS_NP					0xC000

/* Port management ID values */
#define NULL_MANAGEMENT					0x0000
#define CLOCK_DESCRIPTION				0x0001
#define PORT_DATA_SET					0x2004
#define LOG_ANNOUNCE_INTERVAL				0x2009
#define ANNOUNCE_RECEIPT_TIMEOUT			0x200A
#define LOG_SYNC_INTERVAL				0x200B
#define VERSION_NUMBER					0x200C
#define ENABLE_PORT					0x200D
#define DISABLE_PORT					0x200E
#define UNICAST_NEGOTIATION_ENABLE			0x2014
#define UNICAST_MASTER_TABLE				0x2018
#define UNICAST_MASTER_MAX_TABLE_SIZE			0x2019
#define ACCEPTABLE_MASTER_TABLE_ENABLED			0x201B
#define ALTERNATE_MASTER				0x201D
#define TRANSPARENT_CLOCK_PORT_DATA_SET			0x4001
#define DELAY_MECHANISM					0x6000
#define LOG_MIN_PDELAY_REQ_INTERVAL			0x6001

/* Management error ID values */
#define RESPONSE_TOO_BIG				0x0001
#define NO_SUCH_ID					0x0002
#define WRONG_LENGTH					0x0003
#define WRONG_VALUE					0x0004
#define NOT_SETABLE					0x0005
#define NOT_SUPPORTED					0x0006
#define GENERAL_ERROR					0xFFFE

struct management_tlv {
	Enumeration16 type;
	UInteger16    length;
	Enumeration16 id;
	Octet         data[0];
} PACKED;

struct management_error_status {
	Enumeration16 type;
	UInteger16    length;
	Enumeration16 error;
	Enumeration16 id;
	Octet         reserved[4];
	Octet         data[0];
} PACKED;

/* Organizationally Unique Identifiers */
#define IEEE_802_1_COMMITTEE 0x00, 0x80, 0xC2
extern uint8_t ieee8021_id[3];

struct organization_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         id[3];
	Octet         subtype[3];
} PACKED;

#define PATH_TRACE_MAX \
	((sizeof(struct message_data) - sizeof(struct announce_msg) - sizeof(struct TLV)) / \
	 sizeof(struct ClockIdentity))

struct path_trace_tlv {
	Enumeration16 type;
	UInteger16    length;
	struct ClockIdentity cid[0];
} PACKED;

static inline unsigned int path_length(struct path_trace_tlv *p)
{
	return p->length / sizeof(struct ClockIdentity);
}

typedef struct Integer96 {
	uint16_t nanoseconds_msb;
	uint64_t nanoseconds_lsb;
	uint16_t fractional_nanoseconds;
} PACKED ScaledNs;

struct follow_up_info_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         id[3];
	Octet         subtype[3];
	Integer32     cumulativeScaledRateOffset;
	UInteger16    gmTimeBaseIndicator;
	ScaledNs      lastGmPhaseChange;
	Integer32     scaledLastGmPhaseChange;
} PACKED;

struct time_status_np {
	int64_t       master_offset; /*nanoseconds*/
	int64_t       ingress_time;  /*nanoseconds*/
	Integer32     cumulativeScaledRateOffset;
	Integer32     scaledLastGmPhaseChange;
	UInteger16    gmTimeBaseIndicator;
	ScaledNs      lastGmPhaseChange;
	Integer32     gmPresent;
	struct ClockIdentity gmIdentity;
} PACKED;

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
