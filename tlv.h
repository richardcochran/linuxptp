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

#include <sys/queue.h>

#include "ddt.h"
#include "ds.h"

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
#define TLV_AUTHENTICATION_2008				0x2000
#define TLV_AUTHENTICATION_CHALLENGE			0x2001
#define TLV_SECURITY_ASSOCIATION_UPDATE			0x2002
#define TLV_CUM_FREQ_SCALE_FACTOR_OFFSET		0x2003
#define TLV_PTPMON_REQ					0x21FE
#define TLV_PTPMON_RESP					0x21FF
#define TLV_ORGANIZATION_EXTENSION_PROPAGATE		0x4000
#define TLV_ENHANCED_ACCURACY_METRICS			0x4001
#define TLV_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE	0x8000
#define TLV_L1_SYNC					0x8001
#define TLV_PORT_COMMUNICATION_AVAILABILITY		0x8002
#define TLV_PROTOCOL_ADDRESS				0x8003
#define TLV_SLAVE_RX_SYNC_TIMING_DATA			0x8004
#define TLV_SLAVE_RX_SYNC_COMPUTED_DATA			0x8005
#define TLV_SLAVE_TX_EVENT_TIMESTAMPS			0x8006
#define TLV_SLAVE_DELAY_TIMING_DATA_NP			0x7F00
#define TLV_CUMULATIVE_RATE_RATIO			0x8007
#define TLV_PAD						0x8008
#define TLV_AUTHENTICATION				0x8009

enum management_action {
	GET,
	SET,
	RESPONSE,
	COMMAND,
	ACKNOWLEDGE,
};

/* Clock management ID values */
#define MID_USER_DESCRIPTION				0x0002
#define MID_SAVE_IN_NON_VOLATILE_STORAGE		0x0003
#define MID_RESET_NON_VOLATILE_STORAGE			0x0004
#define MID_INITIALIZE					0x0005
#define MID_FAULT_LOG					0x0006
#define MID_FAULT_LOG_RESET				0x0007
#define MID_DEFAULT_DATA_SET				0x2000
#define MID_CURRENT_DATA_SET				0x2001
#define MID_PARENT_DATA_SET				0x2002
#define MID_TIME_PROPERTIES_DATA_SET			0x2003
#define MID_PRIORITY1					0x2005
#define MID_PRIORITY2					0x2006
#define MID_DOMAIN					0x2007
#define MID_SLAVE_ONLY					0x2008
#define MID_TIME					0x200F
#define MID_CLOCK_ACCURACY				0x2010
#define MID_UTC_PROPERTIES				0x2011
#define MID_TRACEABILITY_PROPERTIES			0x2012
#define MID_TIMESCALE_PROPERTIES			0x2013
#define MID_PATH_TRACE_LIST				0x2015
#define MID_PATH_TRACE_ENABLE				0x2016
#define MID_GRANDMASTER_CLUSTER_TABLE			0x2017
#define MID_ACCEPTABLE_MASTER_TABLE			0x201A
#define MID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE		0x201C
#define MID_ALTERNATE_TIME_OFFSET_ENABLE		0x201E
#define MID_ALTERNATE_TIME_OFFSET_NAME			0x201F
#define MID_ALTERNATE_TIME_OFFSET_MAX_KEY		0x2020
#define MID_ALTERNATE_TIME_OFFSET_PROPERTIES		0x2021
#define MID_EXTERNAL_PORT_CONFIGURATION_ENABLED		0x3000
#define MID_HOLDOVER_UPGRADE_ENABLE			0x3002
#define MID_TRANSPARENT_CLOCK_DEFAULT_DATA_SET		0x4000
#define MID_PRIMARY_DOMAIN				0x4002
#define MID_TIME_STATUS_NP				0xC000
#define MID_GRANDMASTER_SETTINGS_NP			0xC001
#define MID_SUBSCRIBE_EVENTS_NP				0xC003
#define MID_SYNCHRONIZATION_UNCERTAIN_NP		0xC006

/* Port management ID values */
#define MID_NULL_MANAGEMENT				0x0000
#define MID_CLOCK_DESCRIPTION				0x0001
#define MID_PORT_DATA_SET				0x2004
#define MID_LOG_ANNOUNCE_INTERVAL			0x2009
#define MID_ANNOUNCE_RECEIPT_TIMEOUT			0x200A
#define MID_LOG_SYNC_INTERVAL				0x200B
#define MID_VERSION_NUMBER				0x200C
#define MID_ENABLE_PORT					0x200D
#define MID_DISABLE_PORT				0x200E
#define MID_UNICAST_NEGOTIATION_ENABLE			0x2014
#define MID_UNICAST_MASTER_TABLE			0x2018
#define MID_UNICAST_MASTER_MAX_TABLE_SIZE		0x2019
#define MID_ACCEPTABLE_MASTER_TABLE_ENABLED		0x201B
#define MID_ALTERNATE_MASTER				0x201D
#define MID_MASTER_ONLY					0x3001
#define MID_EXT_PORT_CONFIG_PORT_DATA_SET		0x3003
#define MID_SLAVE_EVENT_MONITORING			0x3004	// TODO - proposed value, missing in 1588 v2.1
#define MID_TRANSPARENT_CLOCK_PORT_DATA_SET		0x4001
#define MID_DELAY_MECHANISM				0x6000
#define MID_LOG_MIN_PDELAY_REQ_INTERVAL			0x6001
#define MID_PORT_DATA_SET_NP				0xC002
#define MID_PORT_PROPERTIES_NP				0xC004
#define MID_PORT_STATS_NP				0xC005

/* Management error ID values */
#define MID_RESPONSE_TOO_BIG				0x0001
#define MID_NO_SUCH_ID					0x0002
#define MID_WRONG_LENGTH				0x0003
#define MID_WRONG_VALUE					0x0004
#define MID_NOT_SETABLE					0x0005
#define MID_NOT_SUPPORTED				0x0006
#define MID_GENERAL_ERROR				0xFFFE

/* Values for the SYNCHRONIZATION_UNCERTAIN_NP management TLV */
#define SYNC_UNCERTAIN_DONTCARE	0xff
#define SYNC_UNCERTAIN_FALSE	0
#define SYNC_UNCERTAIN_TRUE	1

#define CANCEL_UNICAST_MAINTAIN_REQUEST	(1 << 0)
#define CANCEL_UNICAST_MAINTAIN_GRANT	(1 << 1)
#define GRANT_UNICAST_RENEWAL_INVITED	(1 << 0)

struct ack_cancel_unicast_xmit_tlv {
	Enumeration16   type;
	UInteger16      length;
	uint8_t         message_type_flags;
	uint8_t         reserved;
} PACKED;

struct cancel_unicast_xmit_tlv {
	Enumeration16   type;
	UInteger16      length;
	uint8_t         message_type_flags;
	uint8_t         reserved;
} PACKED;

struct grant_unicast_xmit_tlv {
	Enumeration16   type;
	UInteger16      length;
	uint8_t         message_type;
	Integer8        logInterMessagePeriod;
	UInteger32      durationField;
	uint8_t         reserved;
	uint8_t         flags;
} PACKED;

struct management_tlv {
	Enumeration16 type;
	UInteger16    length;
	Enumeration16 id;
	Octet         data[0];
} PACKED;

struct management_tlv_datum {
	uint8_t val;
	uint8_t reserved;
} PACKED;

struct management_error_status {
	Enumeration16 type;
	UInteger16    length;
	Enumeration16 error;
	Enumeration16 id;
	Octet         reserved[4];
	Octet         data[0];
} PACKED;

struct nsm_resp_tlv_head {
	Enumeration16           type;
	UInteger16              length;
	uint8_t                 port_state;
	uint8_t                 reserved;
	struct PortAddress      parent_addr;
} PACKED;

struct nsm_resp_tlv_foot {
	struct parentDS         parent;
	struct currentDS        current;
	struct timePropertiesDS timeprop;
	struct Timestamp        lastsync;
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

struct request_unicast_xmit_tlv {
	Enumeration16   type;
	UInteger16      length;
	uint8_t         message_type;
	Integer8        logInterMessagePeriod;
	UInteger32      durationField;
} PACKED;

struct slave_delay_timing_record {
	UInteger16          sequenceId;
	struct Timestamp    delayOriginTimestamp;
	TimeInterval        totalCorrectionField;
	struct Timestamp    delayResponseTimestamp;
} PACKED;

struct slave_delay_timing_data_tlv {
	Enumeration16        type;
	UInteger16           length;
	struct PortIdentity  sourcePortIdentity;
	struct slave_delay_timing_record record[0];
} PACKED;

#define SLAVE_DELAY_TIMING_MAX \
	((sizeof(struct message_data) - sizeof(struct signaling_msg) -	\
	  sizeof(struct slave_delay_timing_data_tlv)) /		\
	 sizeof(struct slave_delay_timing_record))

struct slave_rx_sync_timing_record {
	UInteger16          sequenceId;
	struct Timestamp    syncOriginTimestamp;
	TimeInterval        totalCorrectionField;
	Integer32           scaledCumulativeRateOffset;
	struct Timestamp    syncEventIngressTimestamp;
} PACKED;

struct slave_rx_sync_timing_data_tlv {
	Enumeration16        type;
	UInteger16           length;
	struct PortIdentity  sourcePortIdentity;
	struct slave_rx_sync_timing_record record[0];
} PACKED;

#define SLAVE_RX_SYNC_TIMING_MAX \
	((sizeof(struct message_data) - sizeof(struct signaling_msg) -	\
	  sizeof(struct slave_rx_sync_timing_data_tlv)) /		\
	 sizeof(struct slave_rx_sync_timing_record))

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

struct msg_interval_req_tlv {
	Enumeration16 type;
	UInteger16    length;
	Octet         id[3];
	Octet         subtype[3];
	Integer8      linkDelayInterval;
	Integer8      timeSyncInterval;
	Integer8      announceInterval;
	Octet         flags;
	Octet         reserved[2];
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

struct grandmaster_settings_np {
	struct ClockQuality clockQuality;
	Integer16 utc_offset;
	UInteger8 time_flags;
	Enumeration8 time_source;
} PACKED;

struct port_ds_np {
	UInteger32    neighborPropDelayThresh; /*nanoseconds*/
	Integer32     asCapable;
} PACKED;


#define EVENT_BITMASK_CNT 64

struct subscribe_events_np {
	uint16_t      duration; /* seconds */
	uint8_t       bitmask[EVENT_BITMASK_CNT];
} PACKED;

struct port_properties_np {
	struct PortIdentity portIdentity;
	uint8_t port_state;
	uint8_t timestamping;
	struct PTPText interface;
} PACKED;

struct port_stats_np {
	struct PortIdentity portIdentity;
	struct PortStats stats;
} PACKED;

#define PROFILE_ID_LEN 6

struct mgmt_clock_description {
	UInteger16             *clockType;
	struct PTPText         *physicalLayerProtocol;
	struct PhysicalAddress *physicalAddress;
	struct PortAddress     *protocolAddress;
	Octet                  *manufacturerIdentity;
	struct PTPText         *productDescription;
	struct PTPText         *revisionData;
	struct PTPText         *userDescription;
	Octet                  *profileIdentity;
};

struct tlv_extra {
	TAILQ_ENTRY(tlv_extra) list;
	struct TLV *tlv;
	union {
		struct mgmt_clock_description cd;
		struct nsm_resp_tlv_foot *foot;
	};
};

/**
 * Allocates a new tlv_extra structure.
 * @return  Pointer to a new structure on success or NULL otherwise.
 */
struct tlv_extra *tlv_extra_alloc(void);

/**
 * Release all of the memory in the tlv_extra cache.
 */
void tlv_extra_cleanup(void);

/**
 * Frees a tlv_extra structure.
 * @param extra  Pointer to the structure to free.
 */
void tlv_extra_recycle(struct tlv_extra *extra);

/**
 * Converts recognized value sub-fields into host byte order.
 * @param extra  TLV descriptor pointing to the protocol data.
 * @return Zero if successful, otherwise non-zero
 */
int tlv_post_recv(struct tlv_extra *extra);

/**
 * Converts recognized value sub-fields into network byte order.
 * @param tlv Pointer to a Type Length Value field.
 * @param extra Additional struct containing tlv data to send, can be
 * NULL.
 */
void tlv_pre_send(struct TLV *tlv, struct tlv_extra *extra);

#endif
