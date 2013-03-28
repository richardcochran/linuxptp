/**
 * @file msg.h
 * @brief Implements the various PTP message types.
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
#ifndef HAVE_MSG_H
#define HAVE_MSG_H

#include <stdio.h>
#include <sys/queue.h>
#include <time.h>

#include "ddt.h"
#include "transport.h"
#include "tlv.h"

#define PTP_VERSION 2

/* Values for the messageType field */
#define SYNC                  0x0
#define DELAY_REQ             0x1
#define PDELAY_REQ            0x2
#define PDELAY_RESP           0x3
#define FOLLOW_UP             0x8
#define DELAY_RESP            0x9
#define PDELAY_RESP_FOLLOW_UP 0xA
#define ANNOUNCE              0xB
#define SIGNALING             0xC
#define MANAGEMENT            0xD

/* Bits for flagField[0] */
#define ALT_MASTER     (1<<0)
#define TWO_STEP       (1<<1)
#define UNICAST        (1<<2)

/* Bits for flagField[1] */
#define LEAP_61        (1<<0)
#define LEAP_59        (1<<1)
#define UTC_OFF_VALID  (1<<2)
#define PTP_TIMESCALE  (1<<3)
#define TIME_TRACEABLE (1<<4)
#define FREQ_TRACEABLE (1<<5)

enum controlField {
	CTL_SYNC,
	CTL_DELAY_REQ,
	CTL_FOLLOW_UP,
	CTL_DELAY_RESP,
	CTL_MANAGEMENT,
	CTL_OTHER,
};

struct ptp_header {
	uint8_t             tsmt; /* transportSpecific | messageType */
	uint8_t             ver;  /* reserved          | versionPTP  */
	UInteger16          messageLength;
	UInteger8           domainNumber;
	Octet               reserved1;
	Octet               flagField[2];
	Integer64           correction;
	UInteger32          reserved2;
	struct PortIdentity sourcePortIdentity;
	UInteger16          sequenceId;
	UInteger8           control;
	Integer8            logMessageInterval;
} PACKED;

struct announce_msg {
	struct ptp_header    hdr;
	struct Timestamp     originTimestamp;
	Integer16            currentUtcOffset;
	Octet                reserved;
	UInteger8            grandmasterPriority1;
	struct ClockQuality  grandmasterClockQuality;
	UInteger8            grandmasterPriority2;
	struct ClockIdentity grandmasterIdentity;
	UInteger16           stepsRemoved;
	Enumeration8         timeSource;
	uint8_t              suffix[0];
} PACKED;

struct sync_msg {
	struct ptp_header   hdr;
	struct Timestamp    originTimestamp;
} PACKED;

struct delay_req_msg {
	struct ptp_header   hdr;
	struct Timestamp    originTimestamp;
} PACKED;

struct follow_up_msg {
	struct ptp_header   hdr;
	struct Timestamp    preciseOriginTimestamp;
	uint8_t             suffix[0];
} PACKED;

struct delay_resp_msg {
	struct ptp_header   hdr;
	struct Timestamp    receiveTimestamp;
	struct PortIdentity requestingPortIdentity;
	uint8_t             suffix[0];
} PACKED;

struct pdelay_req_msg {
	struct ptp_header   hdr;
	struct Timestamp    originTimestamp;
	struct PortIdentity reserved;
} PACKED;

struct pdelay_resp_msg {
	struct ptp_header   hdr;
	struct Timestamp    requestReceiptTimestamp;
	struct PortIdentity requestingPortIdentity;
} PACKED;

struct pdelay_resp_fup_msg {
	struct ptp_header   hdr;
	struct Timestamp    responseOriginTimestamp;
	struct PortIdentity requestingPortIdentity;
	uint8_t             suffix[0];
} PACKED;

struct signaling_msg {
	struct ptp_header   hdr;
	struct PortIdentity targetPortIdentity;
	uint8_t             suffix[0];
} PACKED;

struct management_msg {
	struct ptp_header   hdr;
	struct PortIdentity targetPortIdentity;
	UInteger8           startingBoundaryHops;
	UInteger8           boundaryHops;
	uint8_t             flags; /* reserved | actionField */
	uint8_t             reserved;
	uint8_t             suffix[0];
} PACKED;

struct message_data {
	uint8_t buffer[1500];
} PACKED;

struct ptp_message {
	union {
		struct ptp_header          header;
		struct announce_msg        announce;
		struct sync_msg            sync;
		struct delay_req_msg       delay_req;
		struct follow_up_msg       follow_up;
		struct delay_resp_msg      delay_resp;
		struct pdelay_req_msg      pdelay_req;
		struct pdelay_resp_msg     pdelay_resp;
		struct pdelay_resp_fup_msg pdelay_resp_fup;
		struct signaling_msg       signaling;
		struct management_msg      management;
		struct message_data        data;
	} PACKED;
	/**/
	int tail_room;
	int refcnt;
	TAILQ_ENTRY(ptp_message) list;
	struct {
		/**
		 * Contains the time stamp from the packet data in a
		 * native binary format for the host machine. The
		 * exact source of the time stamp's value depends on
		 * the message type:
		 *
		 * - announce    originTimestamp
		 * - follow_up   preciseOriginTimestamp
		 * - sync        originTimestamp
		 * - delay_req   originTimestamp
		 * - pdelay_resp     requestReceiptTimestamp
		 * - pdelay_resp_fup responseOriginTimestamp
		 */
		struct timestamp pdu;
		/**
		 * Approximate ingress time stamp using the relative
		 * CLOCK_MONOTONIC. Used to determine when announce
		 * messages have expired.
		 */
		struct timespec host;
	} ts;
	/**
	 * Contains the ingress time stamp obtained by the
	 * SO_TIMESTAMPING socket option.
	 */
	struct hw_timestamp hwts;
	/**
	 * Contains the number of TLVs in the suffix.
	 */
	int tlv_count;
	/**
	 * Used to hold the data of the last TLV in the message when
	 * the layout of the TLV makes it difficult to access the data
	 * directly from the message's buffer.
	 */
	struct tlv_extra last_tlv;
};

/**
 * Obtain the action field from a management message.
 * @param m  A management message.
 * @return   The value of the action field.
 */
static inline uint8_t management_action(struct ptp_message *m)
{
	return m->management.flags & 0x0f;
}

/**
 * Test a given bit in a message's flag field.
 * @param m      Message to test.
 * @param index  Index into flag field, either 0 or 1.
 * @param bit    Bit mask of one bit to test.
 * @return       One if bit is set, zero otherwise.
 */
static inline Boolean field_is_set(struct ptp_message *m, int index, Octet bit)
{
	return m->header.flagField[index] & bit ? TRUE : FALSE;
}

/**
 * Obtain the transportSpecific field from a message.
 * @param m  Message to test.
 * @return   The value of the transportSpecific field. Note that the
 *           value is returned unshifted, in the upper nibble.
 */
static inline UInteger8 msg_transport_specific(struct ptp_message *m)
{
	return m->header.tsmt & 0xf0;
}

/**
 * Obtain the message type.
 * @param m  Message to test.
 * @return   The value of the messageType field.
 */
static inline int msg_type(struct ptp_message *m)
{
	return m->header.tsmt & 0x0f;
}

/**
 * Allocate a new message instance.
 *
 * Messages are reference counted, and newly allocated messages have a
 * reference count of one. Allocated messages are freed using the
 * function @ref msg_put().
 *
 * @return Pointer to a message on success, NULL otherwise.
 */
struct ptp_message *msg_allocate(void);

/**
 * Release all of the memory in the message cache.
 */
void msg_cleanup(void);

/**
 * Obtain a reference to a message, increasing its reference count by one.
 * @param m A message obtained using @ref msg_allocate().
 */
void msg_get(struct ptp_message *m);

/**
 * Process messages after reception.
 * @param m    A message obtained using @ref msg_allocate().
 * @param cnt  The size of 'm' in bytes.
 * @return   Zero on success, non-zero if the message is invalid.
 */
int msg_post_recv(struct ptp_message *m, int cnt);

/**
 * Prepare messages for transmission.
 * @param m  A message obtained using @ref msg_allocate().
 * @return   Zero on success, non-zero if the message is invalid.
 */
int msg_pre_send(struct ptp_message *m);

/**
 * Print messages for debugging purposes.
 * @param type  Value of the messageType field as returned by @ref msg_type().
 * @return      String describing the message type.
 */
char *msg_type_string(int type);

/**
 * Print messages for debugging purposes.
 * @param m   A message obtained using @ref msg_allocate().
 * @param fp  An open file pointer.
 */
void msg_print(struct ptp_message *m, FILE *fp);

/**
 * Release a reference to a message, decreasing its reference count by one.
 * @param m A message obtained using @ref msg_allocate().
 */
void msg_put(struct ptp_message *m);

/**
 * Test whether an event message received a valid SO_TIMESTAMPING time stamp.
 * @param m  Message to test.
 * @return   One if the message is an event without a time stamp, zero otherwise.
 */
int msg_sots_missing(struct ptp_message *m);

/**
 * Work around buggy 802.1AS switches.
 */
extern int assume_two_step;

/**
 * Test whether a message is one-step message.
 * @param m  Message to test.
 * @return   One if the message is a one-step, zero otherwise.
 */
static inline Boolean one_step(struct ptp_message *m)
{
	if (assume_two_step)
		return 0;
	return !field_is_set(m, 0, TWO_STEP);
}

/**
 * Convert a 64 bit word into network byte order.
 */
int64_t host2net64(int64_t val);

/**
 * Convert a 64 bit word into host byte order.
 */
int64_t net2host64(int64_t val);

#endif
