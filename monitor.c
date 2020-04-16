/**
 * @file monitor.c
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdbool.h>
#include <stdlib.h>

#include "address.h"
#include "monitor.h"
#include "print.h"

#define RECORDS_PER_MESSAGE 1

struct monitor_message {
	struct ptp_message *msg;
	int records_per_msg;
	int count;
};

struct monitor {
	struct port *dst_port;
	struct slave_rx_sync_timing_data_tlv *sync_tlv;
	struct slave_delay_timing_data_tlv *delay_tlv;
	struct monitor_message delay;
	struct monitor_message sync;
};

static bool monitor_active(struct monitor *monitor)
{
	return monitor->dst_port ? true : false;
}

static int monitor_forward(struct port *port, struct ptp_message *msg)
{
	int err, pdulen = msg->header.messageLength;

	if (msg_pre_send(msg)) {
		return -1;
	}
	err = port_forward_to(port, msg);
	if (err) {
		pr_debug("failed to send signaling message to slave event monitor: %s",
			 strerror(-err));
	}
	if (msg_post_recv(msg, pdulen)) {
		return -1;
	}
	msg->header.sequenceId++;

	return 0;
}

static struct tlv_extra *monitor_init_message(struct monitor_message *mm,
					      struct port *destination,
					      uint16_t tlv_type,
					      size_t tlv_size,
					      struct address address)
{
	struct ptp_message *msg;
	struct tlv_extra *extra;

	msg = port_signaling_construct(destination, &wildcard_pid);
	if (!msg) {
		return NULL;
	}
	extra = msg_tlv_append(msg, tlv_size);
	if (!extra) {
		msg_put(msg);
		return NULL;
	}
	extra->tlv->type = tlv_type;
	extra->tlv->length = tlv_size - sizeof(extra->tlv->type) -
		sizeof(extra->tlv->length);

	mm->msg = msg;
	mm->msg->address = address;
	mm->records_per_msg = RECORDS_PER_MESSAGE;
	mm->count = 0;

	return extra;
}

static int monitor_init_delay(struct monitor *monitor, struct address address)
{
	const size_t tlv_size = sizeof(struct slave_delay_timing_data_tlv) +
		sizeof(struct slave_delay_timing_record) * RECORDS_PER_MESSAGE;
	struct tlv_extra *extra;

	extra = monitor_init_message(&monitor->delay, monitor->dst_port,
				     TLV_SLAVE_DELAY_TIMING_DATA_NP, tlv_size,
				     address);
	if (!extra) {
		return -1;
	}
	monitor->delay_tlv = (struct slave_delay_timing_data_tlv *) extra->tlv;

	return 0;
}

static int monitor_init_sync(struct monitor *monitor, struct address address)
{
	const size_t tlv_size = sizeof(struct slave_rx_sync_timing_data_tlv) +
		sizeof(struct slave_rx_sync_timing_record) * RECORDS_PER_MESSAGE;
	struct tlv_extra *extra;

	extra = monitor_init_message(&monitor->sync, monitor->dst_port,
				     TLV_SLAVE_RX_SYNC_TIMING_DATA, tlv_size,
				     address);
	if (!extra) {
		return -1;
	}
	monitor->sync_tlv = (struct slave_rx_sync_timing_data_tlv *) extra->tlv;

	return 0;
}

struct monitor *monitor_create(struct config *config, struct port *dst)
{
	struct monitor *monitor;
	struct address address;
	struct sockaddr_un sa;
	const char *path;

	monitor = calloc(1, sizeof(*monitor));
	if (!monitor) {
		return NULL;
	}
	path = config_get_string(config, NULL, "slave_event_monitor");
	if (!path || !path[0]) {
		/* Return an inactive monitor. */
		return monitor;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_LOCAL;
	snprintf(sa.sun_path, sizeof(sa.sun_path) - 1, "%s", path);
	address.sun = sa;
	address.len = sizeof(sa);

	monitor->dst_port = dst;

	if (monitor_init_delay(monitor, address)) {
		free(monitor);
		return NULL;
	}
	if (monitor_init_sync(monitor, address)) {
		msg_put(monitor->delay.msg);
		free(monitor);
		return NULL;
	}

	return monitor;
}

int monitor_delay(struct monitor *monitor, struct PortIdentity source_pid,
		  uint16_t seqid, tmv_t t3, tmv_t corr, tmv_t t4)
{
	struct slave_delay_timing_record *record;
	struct ptp_message *msg;

	if (!monitor_active(monitor)) {
		return 0;
	}

	msg = monitor->delay.msg;

	if (!pid_eq(&monitor->delay_tlv->sourcePortIdentity, &source_pid)) {
		/* There was a change in remote master. Drop stale records. */
		memcpy(&monitor->delay_tlv->sourcePortIdentity, &source_pid,
		       sizeof(monitor->delay_tlv->sourcePortIdentity));
		monitor->delay.count = 0;
	}

	record = monitor->delay_tlv->record + monitor->delay.count;
	record->sequenceId                  = seqid;
	record->delayOriginTimestamp        = tmv_to_Timestamp(t3);
	record->totalCorrectionField        = tmv_to_TimeInterval(corr);
	record->delayResponseTimestamp      = tmv_to_Timestamp(t4);

	monitor->delay.count++;
	if (monitor->delay.count == monitor->delay.records_per_msg) {
		monitor->delay.count = 0;
		return monitor_forward(monitor->dst_port, msg);
	}
	return 0;
}

void monitor_destroy(struct monitor *monitor)
{
	if (monitor->delay.msg) {
		msg_put(monitor->delay.msg);
	}
	if (monitor->sync.msg) {
		msg_put(monitor->sync.msg);
	}
	free(monitor);
}

int monitor_sync(struct monitor *monitor, struct PortIdentity source_pid,
		 uint16_t seqid, tmv_t t1, tmv_t corr, tmv_t t2)
{
	struct slave_rx_sync_timing_record *record;
	struct ptp_message *msg;

	if (!monitor_active(monitor)) {
		return 0;
	}

	msg = monitor->sync.msg;

	if (!pid_eq(&monitor->sync_tlv->sourcePortIdentity, &source_pid)) {
		/* There was a change in remote master. Drop stale records. */
		memcpy(&monitor->sync_tlv->sourcePortIdentity, &source_pid,
		       sizeof(monitor->sync_tlv->sourcePortIdentity));
		monitor->sync.count = 0;
	}

	record = monitor->sync_tlv->record + monitor->sync.count;
	record->sequenceId                 = seqid;
	record->syncOriginTimestamp        = tmv_to_Timestamp(t1);
	record->totalCorrectionField       = tmv_to_TimeInterval(corr);
	record->scaledCumulativeRateOffset = 0;
	record->syncEventIngressTimestamp  = tmv_to_Timestamp(t2);

	monitor->sync.count++;
	if (monitor->sync.count == monitor->sync.records_per_msg) {
		monitor->sync.count = 0;
		return monitor_forward(monitor->dst_port, msg);
	}
	return 0;
}
