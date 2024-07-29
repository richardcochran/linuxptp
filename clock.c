/**
 * @file clock.c
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
#include <errno.h>
#include <time.h>
#include <linux/net_tstamp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

#include "address.h"
#include "bmc.h"
#include "clock.h"
#include "clockadj.h"
#include "clockcheck.h"
#include "foreign.h"
#include "filter.h"
#include "missing.h"
#include "msg.h"
#include "phc.h"
#include "port.h"
#include "sad.h"
#include "servo.h"
#include "stats.h"
#include "print.h"
#include "rtnl.h"
#include "tlv.h"
#include "tsproc.h"
#include "tz.h"
#include "uds.h"
#include "util.h"

#define N_CLOCK_PFD (N_POLLFD + 1) /* one extra per port, for the fault timer */

struct interface {
	STAILQ_ENTRY(interface) list;
};

struct port {
	LIST_ENTRY(port) list;
};

struct freq_estimator {
	tmv_t origin1;
	tmv_t ingress1;
	unsigned int max_count;
	unsigned int count;
};

struct clock_stats {
	struct stats *offset;
	struct stats *freq;
	struct stats *delay;
	unsigned int max_count;
};

struct clock_subscriber {
	LIST_ENTRY(clock_subscriber) list;
	uint8_t events[EVENT_BITMASK_CNT];
	struct PortIdentity targetPortIdentity;
	struct address addr;
	UInteger16 sequenceId;
	time_t expiration;
};

struct time_zone {
	bool enabled;
	int32_t current_offset;
	int32_t jump_seconds;
	uint16_t next_jump_msb;
	uint32_t next_jump_lsb;
	struct static_ptp_text display_name;
};

struct clock {
	enum clock_type type;
	struct config *config;
	clockid_t clkid;
	struct servo *servo;
	enum servo_type servo_type;
	int (*dscmp)(struct dataset *a, struct dataset *b);
	struct defaultDS dds;
	struct dataset default_dataset;
	struct currentDS cur;
	struct parent_ds dad;
	struct timePropertiesDS tds;
	struct ClockIdentity ptl[PATH_TRACE_MAX];
	struct foreign_clock *best;
	struct ClockIdentity best_id;
	LIST_HEAD(ports_head, port) ports;
	struct port *uds_rw_port;
	struct port *uds_ro_port;
	struct pollfd *pollfd;
	int pollfd_valid;
	int nports; /* does not include the two UDS ports */
	int last_port_number;
	int sde;
	int free_running;
	int freq_est_interval;
	int local_sync_uncertain;
	int write_phase_mode;
	int grand_master_capable; /* for 802.1AS only */
	int utc_timescale;
	int utc_offset_set;
	int leap_set;
	int kernel_leap;
	int utc_offset;
	int time_flags;  /* grand master role */
	int time_source; /* grand master role */
	UInteger8 clock_class_threshold;
	UInteger8 max_steps_removed;
	enum servo_state servo_state;
	enum timestamp_type timestamping;
	tmv_t master_offset;
	tmv_t path_delay;
	tmv_t ingress_ts;
	tmv_t initial_delay;
	struct tsproc *tsproc;
	struct freq_estimator fest;
	struct time_status_np status;
	double master_local_rr; /* maintained when free_running */
	double nrr;
	struct clock_description desc;
	struct clock_stats stats;
	int stats_interval;
	struct clockcheck *sanity_check;
	struct interface *uds_rw_if;
	struct interface *uds_ro_if;
	LIST_HEAD(clock_subscribers_head, clock_subscriber) subscribers;
	struct monitor *slave_event_monitor;
	int step_window_counter;
	int step_window;
	struct time_zone tz[MAX_TIME_ZONES];
};

struct clock the_clock;

static void handle_state_decision_event(struct clock *c);
static int clock_resize_pollfd(struct clock *c, int new_nports);
static void clock_remove_port(struct clock *c, struct port *p);
static void clock_stats_display(struct clock_stats *s);

static int clock_alttime_offset_append(struct clock *c, int key, struct ptp_message *m)
{
	struct alternate_time_offset_indicator_tlv *atoi;
	struct tlv_extra *extra;
	int tlv_len;

	tlv_len = sizeof(*atoi) + c->tz[key].display_name.length;
	if (tlv_len % 2) {
		tlv_len++;
	}
	extra = msg_tlv_append(m, tlv_len);
	if (!extra) {
		return -1;
	}
	atoi = (struct alternate_time_offset_indicator_tlv *) extra->tlv;
	atoi->type = TLV_ALTERNATE_TIME_OFFSET_INDICATOR;
	atoi->length = tlv_len - sizeof(atoi->type) - sizeof(atoi->length);
	atoi->keyField = key;

	/* Message alignment broken by design. */
	memcpy(&atoi->currentOffset, &c->tz[key].current_offset,
	       sizeof(atoi->currentOffset));

	memcpy(&atoi->jumpSeconds, &c->tz[key].jump_seconds,
	       sizeof(atoi->jumpSeconds));

	memcpy(&atoi->timeOfNextJump.seconds_lsb, &c->tz[key].next_jump_lsb,
	       sizeof(atoi->timeOfNextJump.seconds_lsb));

	memcpy(&atoi->timeOfNextJump.seconds_msb, &c->tz[key].next_jump_msb,
	       sizeof(atoi->timeOfNextJump.seconds_msb));

	ptp_text_copy(&atoi->displayName, &c->tz[key].display_name);

	return 0;
}

uint8_t clock_alttime_offset_get_key(struct ptp_message *req)
{
	struct management_tlv_datum *mtd;
	struct management_tlv *mgt =
		(struct management_tlv *) req->management.suffix;

	/*
	 * The data field of incoming management request messages is
	 * normally ignored.  Indeed it can even be empty.  However
	 * the ALTERNATE_TIME_OFFSET requests are exceptional because
	 * the key field selects one of the configured time zones.
	 *
	 * Provide the first time zone for an empty GET, and validate
	 * the length of the request when non-empty.
	 */
	if (mgt->length == sizeof(mgt->id)) {
		return 0;
	}
	if (mgt->length < sizeof(mgt->id) + sizeof(*mtd)) {
		return MAX_TIME_ZONES;
	}
	mtd = (struct management_tlv_datum *) mgt->data;

	return mtd->val;
}

static void remove_subscriber(struct clock_subscriber *s)
{
	LIST_REMOVE(s, list);
	free(s);
}

static void clock_update_subscription(struct clock *c, struct ptp_message *req,
				      uint8_t *bitmask, uint16_t duration)
{
	struct clock_subscriber *s, *tmp;
	struct timespec now;
	int i, remove = 1;

	for (i = 0; i < EVENT_BITMASK_CNT; i++) {
		if (bitmask[i]) {
			remove = 0;
			break;
		}
	}

	LIST_FOREACH_SAFE(s, &c->subscribers, list, tmp) {
		if (pid_eq(&s->targetPortIdentity,
			   &req->header.sourcePortIdentity)) {
			if (!remove) {
				/* Update transport address and event mask. */
				s->addr = req->address;
				memcpy(s->events, bitmask, EVENT_BITMASK_CNT);
				clock_gettime(CLOCK_MONOTONIC, &now);
				/* Subscription will not expire if the duration is set to UINT16_MAX. */
				s->expiration = duration != UINT16_MAX ? now.tv_sec + duration : 0;
			} else {
				remove_subscriber(s);
			}
			return;
		}
	}
	if (remove)
		return;
	/* Not present yet, add the subscriber. */
	s = malloc(sizeof(*s));
	if (!s) {
		pr_err("failed to allocate memory for a subscriber");
		return;
	}
	s->targetPortIdentity = req->header.sourcePortIdentity;
	s->addr = req->address;
	memcpy(s->events, bitmask, EVENT_BITMASK_CNT);
	clock_gettime(CLOCK_MONOTONIC, &now);
	/* Subscription will not expire if the duration is set to UINT16_MAX. */
	s->expiration = duration != UINT16_MAX ? now.tv_sec + duration : 0;
	s->sequenceId = 0;
	LIST_INSERT_HEAD(&c->subscribers, s, list);
}

static void clock_get_subscription(struct clock *c, struct ptp_message *req,
				   uint8_t *bitmask, uint16_t *duration)
{
	struct clock_subscriber *s;
	struct timespec now;

	LIST_FOREACH(s, &c->subscribers, list) {
		if (pid_eq(&s->targetPortIdentity,
			   &req->header.sourcePortIdentity)) {
			memcpy(bitmask, s->events, EVENT_BITMASK_CNT);
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (s->expiration < now.tv_sec)
				*duration = 0;
			else
				*duration = s->expiration - now.tv_sec;
			return;
		}
	}
	/* A client without entry means the client has no subscriptions. */
	memset(bitmask, 0, EVENT_BITMASK_CNT);
	*duration = 0;
}

static void clock_flush_subscriptions(struct clock *c)
{
	struct clock_subscriber *s, *tmp;

	LIST_FOREACH_SAFE(s, &c->subscribers, list, tmp) {
		remove_subscriber(s);
	}
}

static void clock_prune_subscriptions(struct clock *c)
{
	struct clock_subscriber *s, *tmp;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	LIST_FOREACH_SAFE(s, &c->subscribers, list, tmp) {
		if (s->expiration != 0 && s->expiration <= now.tv_sec) {
			pr_info("subscriber %s timed out",
				pid2str(&s->targetPortIdentity));
			remove_subscriber(s);
		}
	}
}

void clock_send_notification(struct clock *c, struct ptp_message *msg,
			     enum notification event)
{
	struct port *uds = c->uds_rw_port;
	struct clock_subscriber *s;

	LIST_FOREACH(s, &c->subscribers, list) {
		if (!event_bitmask_get(s->events, event))
			continue;
		/* send event */
		msg->header.sequenceId = htons(s->sequenceId);
		s->sequenceId++;
		msg->management.targetPortIdentity.clockIdentity =
			s->targetPortIdentity.clockIdentity;
		msg->management.targetPortIdentity.portNumber =
			htons(s->targetPortIdentity.portNumber);
		msg->address = s->addr;
		sad_update_auth_tlv(clock_config(c), msg);
		port_forward_to(uds, msg);
	}
}

void clock_destroy(struct clock *c)
{
	struct port *p, *tmp;

	interface_destroy(c->uds_rw_if);
	interface_destroy(c->uds_ro_if);
	clock_flush_subscriptions(c);
	LIST_FOREACH_SAFE(p, &c->ports, list, tmp) {
		clock_remove_port(c, p);
	}
	monitor_destroy(c->slave_event_monitor);
	port_close(c->uds_rw_port);
	port_close(c->uds_ro_port);
	free(c->pollfd);
	if (c->clkid != CLOCK_REALTIME) {
		phc_close(c->clkid);
	}
	servo_destroy(c->servo);
	tsproc_destroy(c->tsproc);
	stats_destroy(c->stats.offset);
	stats_destroy(c->stats.freq);
	stats_destroy(c->stats.delay);
	if (c->sanity_check) {
		clockcheck_destroy(c->sanity_check);
	}
	memset(c, 0, sizeof(*c));
	msg_cleanup();
	tc_cleanup();
}

static int clock_fault_timeout(struct port *port, int set)
{
	struct fault_interval i;

	if (!set) {
		pr_debug("clearing fault on %s", port_log_name(port));
		return port_set_fault_timer_lin(port, 0);
	}

	fault_interval(port, last_fault_type(port), &i);

	if (i.type == FTMO_LINEAR_SECONDS) {
		pr_debug("waiting %d seconds to clear fault on %s",
			 i.val, port_log_name(port));
		return port_set_fault_timer_lin(port, i.val);
	} else if (i.type == FTMO_LOG2_SECONDS) {
		pr_debug("waiting 2^{%d} seconds to clear fault on %s",
			 i.val, port_log_name(port));
		return port_set_fault_timer_log(port, 1, i.val);
	}

	pr_err("Unsupported fault interval type %d", i.type);
	return -1;
}

static void clock_freq_est_reset(struct clock *c)
{
	c->fest.origin1 = tmv_zero();
	c->fest.ingress1 = tmv_zero();
	c->fest.count = 0;
}

static void clock_management_send_error(struct port *p,
					struct ptp_message *msg, int error_id)
{
	if (port_management_error(port_identity(p), p, msg, error_id))
		pr_err("failed to send management error status");
}

/* The 'p' and 'req' paremeters are needed for the GET actions that operate
 * on per-client datasets. If such actions do not apply to the caller, it is
 * allowed to pass both of them as NULL.
 */
static int clock_management_fill_response(struct clock *c, struct port *p,
					  struct ptp_message *req,
					  struct ptp_message *rsp, int id)
{
	struct alternate_time_offset_properties *atop;
	struct alternate_time_offset_name *aton;
	struct grandmaster_settings_np *gsn;
	struct management_tlv_datum *mtd;
	struct subscribe_events_np *sen;
	struct management_tlv *tlv;
	struct time_status_np *tsn;
	struct tlv_extra *extra;
	struct PTPText *text;
	uint16_t duration;
	int datalen = 0;
	uint8_t key;

	extra = tlv_extra_alloc();
	if (!extra) {
		pr_err("failed to allocate TLV descriptor");
		return 0;
	}
	extra->tlv = (struct TLV *) rsp->management.suffix;

	tlv = (struct management_tlv *) rsp->management.suffix;
	tlv->type = TLV_MANAGEMENT;
	tlv->id = id;

	switch (id) {
	case MID_USER_DESCRIPTION:
		text = (struct PTPText *) tlv->data;
		text->length = c->desc.userDescription.length;
		memcpy(text->text, c->desc.userDescription.text, text->length);
		datalen = 1 + text->length;
		break;
	case MID_DEFAULT_DATA_SET:
		memcpy(tlv->data, &c->dds, sizeof(c->dds));
		datalen = sizeof(c->dds);
		break;
	case MID_CURRENT_DATA_SET:
		memcpy(tlv->data, &c->cur, sizeof(c->cur));
		datalen = sizeof(c->cur);
		break;
	case MID_PARENT_DATA_SET:
		memcpy(tlv->data, &c->dad.pds, sizeof(c->dad.pds));
		datalen = sizeof(c->dad.pds);
		break;
	case MID_TIME_PROPERTIES_DATA_SET:
		memcpy(tlv->data, &c->tds, sizeof(c->tds));
		datalen = sizeof(c->tds);
		break;
	case MID_PRIORITY1:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->dds.priority1;
		datalen = sizeof(*mtd);
		break;
	case MID_PRIORITY2:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->dds.priority2;
		datalen = sizeof(*mtd);
		break;
	case MID_DOMAIN:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->dds.domainNumber;
		datalen = sizeof(*mtd);
		break;
	case MID_SLAVE_ONLY:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->dds.flags & DDS_SLAVE_ONLY ? 1 : 0;
		datalen = sizeof(*mtd);
		break;
	case MID_CLOCK_ACCURACY:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->dds.clockQuality.clockAccuracy;
		datalen = sizeof(*mtd);
		break;
	case MID_TRACEABILITY_PROPERTIES:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->tds.flags & (TIME_TRACEABLE|FREQ_TRACEABLE);
		datalen = sizeof(*mtd);
		break;
	case MID_TIMESCALE_PROPERTIES:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->tds.flags & PTP_TIMESCALE;
		datalen = sizeof(*mtd);
		break;
	case MID_ALTERNATE_TIME_OFFSET_ENABLE:
		key = clock_alttime_offset_get_key(req);
		if (key >= MAX_TIME_ZONES) {
			break;
		}
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = key;
		mtd->reserved = c->tz[key].enabled ? 1 : 0;
		datalen = sizeof(*mtd);
		break;
	case MID_ALTERNATE_TIME_OFFSET_NAME:
		key = clock_alttime_offset_get_key(req);
		if (key >= MAX_TIME_ZONES) {
			break;
		}
		aton = (struct alternate_time_offset_name *) tlv->data;
		aton->keyField = key;
		ptp_text_copy(&aton->displayName, &c->tz[key].display_name);
		datalen = sizeof(*aton) + aton->displayName.length;
		break;
	case MID_ALTERNATE_TIME_OFFSET_PROPERTIES:
		key = clock_alttime_offset_get_key(req);
		if (key >= MAX_TIME_ZONES) {
			break;
		}
		atop = (struct alternate_time_offset_properties *) tlv->data;
		atop->keyField = key;
		/* Message alignment broken by design. */
		memcpy(&atop->currentOffset, &c->tz[key].current_offset,
		       sizeof(atop->currentOffset));
		memcpy(&atop->jumpSeconds, &c->tz[key].jump_seconds,
		       sizeof(atop->jumpSeconds));
		memcpy(&atop->timeOfNextJump.seconds_lsb, &c->tz[key].next_jump_lsb,
		       sizeof(atop->timeOfNextJump.seconds_lsb));
		memcpy(&atop->timeOfNextJump.seconds_msb, &c->tz[key].next_jump_msb,
		       sizeof(atop->timeOfNextJump.seconds_msb));
		datalen = sizeof(*atop);
		break;
	case MID_TIME_STATUS_NP:
		tsn = (struct time_status_np *) tlv->data;
		tsn->master_offset = tmv_to_nanoseconds(c->master_offset);
		tsn->ingress_time = tmv_to_nanoseconds(c->ingress_ts);
		tsn->cumulativeScaledRateOffset =
			(Integer32) (c->status.cumulativeScaledRateOffset +
				      c->nrr * POW2_41 - POW2_41);
		tsn->scaledLastGmPhaseChange = c->status.scaledLastGmPhaseChange;
		tsn->gmTimeBaseIndicator = c->status.gmTimeBaseIndicator;
		tsn->lastGmPhaseChange = c->status.lastGmPhaseChange;
		if (cid_eq(&c->dad.pds.grandmasterIdentity, &c->dds.clockIdentity))
			tsn->gmPresent = 0;
		else
			tsn->gmPresent = 1;
		tsn->gmIdentity = c->dad.pds.grandmasterIdentity;
		datalen = sizeof(*tsn);
		break;
	case MID_GRANDMASTER_SETTINGS_NP:
		gsn = (struct grandmaster_settings_np *) tlv->data;
		gsn->clockQuality = c->dds.clockQuality;
		gsn->utc_offset = c->utc_offset;
		gsn->time_flags = c->time_flags;
		gsn->time_source = c->time_source;
		datalen = sizeof(*gsn);
		break;
	case MID_SUBSCRIBE_EVENTS_NP:
		if (p != c->uds_rw_port) {
			/* Only the UDS-RW port allowed. */
			break;
		}
		sen = (struct subscribe_events_np *)tlv->data;
		clock_get_subscription(c, req, sen->bitmask, &duration);
		memcpy(&sen->duration, &duration, sizeof(sen->duration));
		datalen = sizeof(*sen);
		break;
	case MID_SYNCHRONIZATION_UNCERTAIN_NP:
		mtd = (struct management_tlv_datum *) tlv->data;
		mtd->val = c->local_sync_uncertain;
		datalen = sizeof(*mtd);
		break;
	default:
		/* The caller should *not* respond to this message. */
		tlv_extra_recycle(extra);
		return 0;
	}
	if (datalen % 2) {
		tlv->data[datalen] = 0;
		datalen++;
	}
	tlv->length = sizeof(tlv->id) + datalen;
	rsp->header.messageLength += sizeof(*tlv) + datalen;
	msg_tlv_attach(rsp, extra);

	/* The caller can respond to this message. */
	return 1;
}

static int clock_management_get_response(struct clock *c, struct port *p,
					 int id, struct ptp_message *req)
{
	struct PortIdentity pid = port_identity(p);
	struct ptp_message *rsp;
	int respond;

	rsp = port_management_reply(pid, p, req);
	if (!rsp) {
		return 0;
	}
	respond = clock_management_fill_response(c, p, req, rsp, id);
	if (respond)
		port_prepare_and_send(p, rsp, TRANS_GENERAL);
	msg_put(rsp);
	return respond;
}

static int clock_management_set(struct clock *c, struct port *p,
				int id, struct ptp_message *req, int *changed)
{
	struct alternate_time_offset_properties *atop;
	struct alternate_time_offset_name *aton;
	struct grandmaster_settings_np *gsn;
	struct management_tlv_datum *mtd;
	struct subscribe_events_np *sen;
	struct management_tlv *tlv;
	int k, key, respond = 0;

	tlv = (struct management_tlv *) req->management.suffix;

	switch (id) {
	case MID_PRIORITY1:
		mtd = (struct management_tlv_datum *) tlv->data;
		c->dds.priority1 = mtd->val;
		*changed = 1;
		respond = 1;
		break;
	case MID_PRIORITY2:
		mtd = (struct management_tlv_datum *) tlv->data;
		c->dds.priority2 = mtd->val;
		*changed = 1;
		respond = 1;
		break;
	case MID_ALTERNATE_TIME_OFFSET_ENABLE:
		mtd = (struct management_tlv_datum *) tlv->data;
		key = mtd->val;
		if (key == 0xff) {
			for (k = 0; k < MAX_TIME_ZONES; k++) {
				c->tz[k].enabled = mtd->reserved & 1 ? true : false;
			}
			respond = 1;
		}
		if (key < MAX_TIME_ZONES) {
			c->tz[key].enabled = mtd->reserved & 1 ? true : false;
			respond = 1;
		}
		break;
	case MID_ALTERNATE_TIME_OFFSET_NAME:
		aton = (struct alternate_time_offset_name *) tlv->data;
		key = aton->keyField;
		if (key < MAX_TIME_ZONES &&
		    !static_ptp_text_copy(&c->tz[key].display_name, &aton->displayName)) {
			respond = 1;
		}
		break;
	case MID_ALTERNATE_TIME_OFFSET_PROPERTIES:
		atop = (struct alternate_time_offset_properties *) tlv->data;
		key = atop->keyField;
		if (key < MAX_TIME_ZONES) {
			/* Message alignment broken by design. */
			memcpy(&c->tz[key].current_offset, &atop->currentOffset,
			       sizeof(c->tz[key].current_offset));
			memcpy(&c->tz[key].jump_seconds, &atop->jumpSeconds,
			       sizeof(c->tz[key].jump_seconds));
			memcpy(&c->tz[key].next_jump_lsb, &atop->timeOfNextJump.seconds_lsb,
			       sizeof(c->tz[key].next_jump_lsb));
			memcpy(&c->tz[key].next_jump_msb, &atop->timeOfNextJump.seconds_msb,
			       sizeof(c->tz[key].next_jump_msb));
			respond = 1;
		}
		break;
	case MID_GRANDMASTER_SETTINGS_NP:
		gsn = (struct grandmaster_settings_np *) tlv->data;
		c->dds.clockQuality = gsn->clockQuality;
		c->utc_offset = gsn->utc_offset;
		c->time_flags = gsn->time_flags;
		c->time_source = gsn->time_source;
		*changed = 1;
		respond = 1;
		break;
	case MID_SUBSCRIBE_EVENTS_NP:
		sen = (struct subscribe_events_np *)tlv->data;
		clock_update_subscription(c, req, sen->bitmask, sen->duration);
		respond = 1;
		break;
	case MID_SYNCHRONIZATION_UNCERTAIN_NP:
		mtd = (struct management_tlv_datum *) tlv->data;
		switch (mtd->val) {
		case SYNC_UNCERTAIN_DONTCARE:
		case SYNC_UNCERTAIN_FALSE:
		case SYNC_UNCERTAIN_TRUE:
			/* Display stats on change of local_sync_uncertain */
			if (c->local_sync_uncertain != mtd->val
			    && stats_get_num_values(c->stats.offset))
				clock_stats_display(&c->stats);
			c->local_sync_uncertain = mtd->val;
			respond = 1;
			break;
		}
		break;
	}
	if (respond && !clock_management_get_response(c, p, id, req))
		pr_err("failed to send management set response");
	return respond ? 1 : 0;
}

static void clock_stats_update(struct clock_stats *s,
			       double offset, double freq)
{
	stats_add_value(s->offset, offset);
	stats_add_value(s->freq, freq);

	if (stats_get_num_values(s->offset) < s->max_count)
		return;

	clock_stats_display(s);
}

static void clock_stats_display(struct clock_stats *s)
{
	struct stats_result offset_stats, freq_stats, delay_stats;

	stats_get_result(s->offset, &offset_stats);
	stats_get_result(s->freq, &freq_stats);

	/* Path delay stats are updated separately, they may be empty. */
	if (!stats_get_result(s->delay, &delay_stats)) {
		pr_info("rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f "
			"delay %5.0f +/- %3.0f",
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev,
			delay_stats.mean, delay_stats.stddev);
	} else {
		pr_info("rms %4.0f max %4.0f "
			"freq %+6.0f +/- %3.0f",
			offset_stats.rms, offset_stats.max_abs,
			freq_stats.mean, freq_stats.stddev);
	}

	stats_reset(s->offset);
	stats_reset(s->freq);
	stats_reset(s->delay);
}

static enum servo_state clock_no_adjust(struct clock *c, tmv_t ingress,
					tmv_t origin)
{
	struct freq_estimator *f = &c->fest;
	double freq, fui, ratio;
	enum servo_state state;

	if (c->local_sync_uncertain == SYNC_UNCERTAIN_FALSE) {
		state = SERVO_LOCKED;
	} else {
		state = SERVO_UNLOCKED;
	}

	/*
	 * The ratio of the local clock freqency to the master clock
	 * is estimated by:
	 *
	 *    (ingress_2 - ingress_1) / (origin_2 - origin_1)
	 *
	 * Both of the origin time estimates include the path delay,
	 * but we assume that the path delay is in fact constant.
	 * By leaving out the path delay altogther, we can avoid the
	 * error caused by our imperfect path delay measurement.
	 */
	if (tmv_is_zero(f->ingress1)) {
		f->ingress1 = ingress;
		f->origin1 = origin;
		return state;
	}
	f->count++;
	if (f->count < f->max_count) {
		return state;
	}
	if (tmv_cmp(ingress, f->ingress1) == 0) {
		pr_warning("bad timestamps in rate ratio calculation");
		return state;
	}

	ratio = tmv_dbl(tmv_sub(origin, f->origin1)) /
		tmv_dbl(tmv_sub(ingress, f->ingress1));
	freq = (1.0 - ratio) * 1e9;

	if (c->stats.max_count > 1) {
		clock_stats_update(&c->stats, tmv_dbl(c->master_offset), freq);
	} else {
		pr_info("master offset %10" PRId64 " s%d freq %+7.0f "
			"path delay %9" PRId64,
			tmv_to_nanoseconds(c->master_offset), state, freq,
			tmv_to_nanoseconds(c->path_delay));
	}

	fui = 1.0 + (c->status.cumulativeScaledRateOffset + 0.0) / POW2_41;

	pr_debug("peer/local    %.9f", c->nrr);
	pr_debug("fup_info      %.9f", fui);
	pr_debug("product       %.9f", fui * c->nrr);
	pr_debug("sum-1         %.9f", fui + c->nrr - 1.0);
	pr_debug("master/local  %.9f", ratio);
	pr_debug("diff         %+.9f", ratio - (fui + c->nrr - 1.0));

	f->ingress1 = ingress;
	f->origin1 = origin;
	f->count = 0;

	c->master_local_rr = ratio;

	return state;
}

static int clock_compare_pds(struct parentDS *pds1, struct parentDS *pds2)
{
	return memcmp(pds1, pds2, sizeof (*pds1));
}

static void clock_update_grandmaster(struct clock *c)
{
	struct parentDS *pds = &c->dad.pds, old_pds = *pds;
	memset(&c->cur, 0, sizeof(c->cur));
	memset(c->ptl, 0, sizeof(c->ptl));

	pds->parentPortIdentity.clockIdentity   = c->dds.clockIdentity;
	/* Follow IEEE 1588 Table 30: Updates for state decision code M1 and M2 */
	pds->parentPortIdentity.portNumber      = 0;
	pds->grandmasterIdentity                = c->dds.clockIdentity;
	pds->grandmasterClockQuality            = c->dds.clockQuality;
	pds->grandmasterPriority1               = c->dds.priority1;
	pds->grandmasterPriority2               = c->dds.priority2;
	c->dad.path_length                      = 0;
	c->tds.currentUtcOffset                 = c->utc_offset;
	c->tds.flags                            = c->time_flags;
	c->tds.timeSource                       = c->time_source;

	if (clock_compare_pds(&old_pds, pds))
		clock_notify_event(c, NOTIFY_PARENT_DATA_SET);
}

static void clock_update_slave(struct clock *c)
{
	struct parentDS *pds = &c->dad.pds, old_pds = *pds;
	struct timePropertiesDS tds;
	struct ptp_message *msg;

	if (!c->best)
		return;

	msg                            = TAILQ_FIRST(&c->best->messages);
	c->cur.stepsRemoved            = 1 + c->best->dataset.stepsRemoved;
	pds->parentPortIdentity        = c->best->dataset.sender;
	pds->grandmasterIdentity       = msg->announce.grandmasterIdentity;
	pds->grandmasterClockQuality   = msg->announce.grandmasterClockQuality;
	pds->grandmasterPriority1      = msg->announce.grandmasterPriority1;
	pds->grandmasterPriority2      = msg->announce.grandmasterPriority2;
	tds.currentUtcOffset           = msg->announce.currentUtcOffset;
	tds.flags                      = msg->header.flagField[1];
	tds.timeSource                 = msg->announce.timeSource;
	if (!(tds.flags & PTP_TIMESCALE)) {
		pr_warning("foreign master not using PTP timescale");
	}
	if (tds.currentUtcOffset < c->utc_offset) {
		pr_warning("running in a temporal vortex");
	}
	clock_update_time_properties(c, tds);

	if (clock_compare_pds(&old_pds, pds))
		clock_notify_event(c, NOTIFY_PARENT_DATA_SET);
}

static int clock_utc_correct(struct clock *c, tmv_t ingress)
{
	struct timespec offset;
	int utc_offset, leap, clock_leap;
	uint64_t ts;

	if (!c->utc_timescale && c->tds.flags & PTP_TIMESCALE)
		return 0;

	utc_offset = c->utc_offset;

	if (c->tds.flags & LEAP_61) {
		leap = 1;
	} else if (c->tds.flags & LEAP_59) {
		leap = -1;
	} else {
		leap = 0;
	}

	/* Handle leap seconds. */
	if (leap || c->leap_set) {
		/* If the clock will be stepped, the time stamp has to be the
		   target time. Ignore possible 1 second error in utc_offset. */
		if (c->servo_state == SERVO_UNLOCKED) {
			ts = tmv_to_nanoseconds(tmv_sub(ingress,
							c->master_offset));
			if (c->tds.flags & PTP_TIMESCALE)
				ts -= utc_offset * NS_PER_SEC;
		} else {
			ts = tmv_to_nanoseconds(ingress);
		}

		/* Suspend clock updates in the last second before midnight. */
		if (is_utc_ambiguous(ts)) {
			pr_info("clock update suspended due to leap second");
			return -1;
		}

		clock_leap = leap_second_status(ts, c->leap_set,
						&leap, &utc_offset);
		if (c->leap_set != clock_leap) {
			if (c->kernel_leap && c->clkid == CLOCK_REALTIME)
				sysclk_set_leap(clock_leap);
			else
				servo_leap(c->servo, clock_leap);
			c->leap_set = clock_leap;
		}
	}

	/* Update TAI-UTC offset of the system clock if valid and traceable. */
	if (c->tds.flags & UTC_OFF_VALID && c->tds.flags & TIME_TRACEABLE &&
	    c->utc_offset_set != utc_offset && c->clkid == CLOCK_REALTIME) {
		sysclk_set_tai_offset(utc_offset);
		c->utc_offset_set = utc_offset;
	}

	if (!(c->tds.flags & PTP_TIMESCALE))
		return 0;

	offset.tv_sec = utc_offset;
	offset.tv_nsec = 0;
	/* Local clock is UTC, but master is TAI. */
	c->master_offset = tmv_add(c->master_offset, timespec_to_tmv(offset));
	return 0;
}

static int forwarding(struct clock *c, struct port *p)
{
	enum port_state ps = port_state(p);

	if (p == c->uds_ro_port)
		return 0;

	switch (ps) {
	case PS_MASTER:
	case PS_GRAND_MASTER:
	case PS_SLAVE:
	case PS_UNCALIBRATED:
	case PS_PRE_MASTER:
		return 1;
	default:
		break;
	}
	if (p == c->uds_rw_port && ps != PS_FAULTY) {
		return 1;
	}
	return 0;
}

/* public methods */

int clock_append_timezones(struct clock *c, struct ptp_message *m)
{
	int err = 0, i;

	for (i = 0; i < MAX_TIME_ZONES; i++) {
		if (!c->tz[i].enabled) {
			continue;
		}
		err = clock_alttime_offset_append(c, i, m);
		if (err) {
			break;
		}
	}
	return err;
}

UInteger8 clock_class(struct clock *c)
{
	return c->dds.clockQuality.clockClass;
}

struct config *clock_config(struct clock *c)
{
	return c->config;
}

int (*clock_dscmp(struct clock *c))(struct dataset *a, struct dataset *b)
{
	return c->dscmp;
}

struct currentDS *clock_current_dataset(struct clock *c)
{
	return &c->cur;
}

static int clock_add_port(struct clock *c, const char *phc_device,
			  int phc_index, enum timestamp_type timestamping,
			  struct interface *iface)
{
	struct port *p, *piter, *lastp = NULL;

	if (clock_resize_pollfd(c, c->nports + 2)) {
		return -1;
	}
	p = port_open(phc_device, phc_index, timestamping,
		      ++c->last_port_number, iface, c);
	if (!p) {
		/* No need to shrink pollfd */
		return -1;
	}
	LIST_FOREACH(piter, &c->ports, list) {
		lastp = piter;
	}
	if (lastp) {
		LIST_INSERT_AFTER(lastp, p, list);
	} else {
		LIST_INSERT_HEAD(&c->ports, p, list);
	}
	c->nports++;
	clock_fda_changed(c);

	return 0;
}

static void clock_remove_port(struct clock *c, struct port *p)
{
	/* Do not call clock_resize_pollfd, it's pointless to shrink
	 * the allocated memory at this point, clock_destroy will free
	 * it all anyway. This function is usable from other parts of
	 * the code, but even then we don't mind if pollfd is larger
	 * than necessary. */
	LIST_REMOVE(p, list);
	c->nports--;
	clock_fda_changed(c);
	port_close(p);
}

int clock_required_modes(struct clock *c)
{
	int required_modes = 0;

	switch (c->timestamping) {
	case TS_SOFTWARE:
		required_modes |= SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
		break;
	case TS_LEGACY_HW:
		required_modes |= SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_SYS_HARDWARE;
		break;
	case TS_HARDWARE:
	case TS_ONESTEP:
	case TS_P2P1STEP:
		required_modes |= SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;
		break;
	default:
		break;
	}

	return required_modes;
}

struct clock *clock_create(enum clock_type type, struct config *config,
			   const char *phc_device)
{
	int conf_phc_index, i, max_adj = 0, phc_index, required_modes = 0, sfl, sw_ts;
	enum servo_type servo = config_get_int(config, NULL, "clock_servo");
	char ts_label[IF_NAMESIZE], phc[32], *tmp;
	enum timestamp_type timestamping;
	struct clock *c = &the_clock;
	const char *uds_ifname;
	double fadj = 0.0;
	struct port *p;
	unsigned char oui[OUI_LEN];
	struct interface *iface;
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	srandom(ts.tv_sec ^ ts.tv_nsec);

	if (c->nports) {
		clock_destroy(c);
	}

	switch (type) {
	case CLOCK_TYPE_ORDINARY:
	case CLOCK_TYPE_BOUNDARY:
	case CLOCK_TYPE_P2P:
	case CLOCK_TYPE_E2E:
		c->type = type;
		break;
	case CLOCK_TYPE_MANAGEMENT:
		return NULL;
	}

	/* Initialize the defaultDS. */
	c->dds.clockQuality.clockClass =
		config_get_int(config, NULL, "clockClass");
	c->dds.clockQuality.clockAccuracy =
		config_get_int(config, NULL, "clockAccuracy");
	c->dds.clockQuality.offsetScaledLogVariance =
		config_get_int(config, NULL, "offsetScaledLogVariance");

	c->desc.productDescription.max_symbols = 64;
	c->desc.revisionData.max_symbols = 32;
	c->desc.userDescription.max_symbols = 128;

	tmp = config_get_string(config, NULL, "productDescription");
	if (count_char(tmp, ';') != 2 ||
	    static_ptp_text_set(&c->desc.productDescription, tmp)) {
		pr_err("invalid productDescription '%s'", tmp);
		return NULL;
	}
	tmp = config_get_string(config, NULL, "revisionData");
	if (count_char(tmp, ';') != 2 ||
	    static_ptp_text_set(&c->desc.revisionData, tmp)) {
		pr_err("invalid revisionData '%s'", tmp);
		return NULL;
	}
	tmp = config_get_string(config, NULL, "userDescription");
	if (static_ptp_text_set(&c->desc.userDescription, tmp)) {
		pr_err("invalid userDescription '%s'", tmp);
		return NULL;
	}
	tmp = config_get_string(config, NULL, "manufacturerIdentity");
	if (OUI_LEN != sscanf(tmp, "%hhx:%hhx:%hhx", &oui[0], &oui[1], &oui[2])) {
		pr_err("invalid manufacturerIdentity '%s'", tmp);
		return NULL;
	}
	memcpy(c->desc.manufacturerIdentity, oui, OUI_LEN);

	c->dds.domainNumber = config_get_int(config, NULL, "domainNumber");

	if (config_get_int(config, NULL, "clientOnly")) {
		c->dds.flags |= DDS_SLAVE_ONLY;
	}
	if (!config_get_int(config, NULL, "gmCapable") &&
	    c->dds.flags & DDS_SLAVE_ONLY) {
		pr_err("Cannot mix 1588 clientOnly with 802.1AS !gmCapable");
		return NULL;
	}
	if (!config_get_int(config, NULL, "gmCapable") ||
	    c->dds.flags & DDS_SLAVE_ONLY) {
		c->dds.clockQuality.clockClass = 255;
	}
	c->default_dataset.localPriority =
		config_get_int(config, NULL, "G.8275.defaultDS.localPriority");
	c->max_steps_removed = config_get_int(config, NULL,"maxStepsRemoved");
	c->clock_class_threshold = config_get_int(config, NULL, "clock_class_threshold");

	/* Harmonize the twoStepFlag with the time_stamping option. */
	if (config_harmonize_onestep(config)) {
		return NULL;
	}
	if (config_get_int(config, NULL, "twoStepFlag")) {
		c->dds.flags |= DDS_TWO_STEP_FLAG;
	}
	timestamping = config_get_int(config, NULL, "time_stamping");
	if (timestamping == TS_SOFTWARE) {
		sw_ts = 1;
	} else {
		sw_ts = 0;
	}

	c->dds.priority1 = config_get_int(config, NULL, "priority1");
	c->dds.priority2 = config_get_int(config, NULL, "priority2");

	/* Check the time stamping mode on each interface. */
	c->timestamping = timestamping;
	required_modes = clock_required_modes(c);
	STAILQ_FOREACH(iface, &config->interfaces, list) {
		memset(ts_label, 0, sizeof(ts_label));
		if (!rtnl_get_ts_device(interface_name(iface), ts_label))
			interface_set_label(iface, ts_label);
		/* Interface speed information */
		interface_get_ifinfo(iface);
		interface_get_tsinfo(iface);
		if (interface_tsinfo_valid(iface) &&
				!interface_tsmodes_supported(iface, required_modes)) {
			pr_err("interface '%s' does not support requested timestamping mode",
					interface_name(iface));
			return NULL;
		}
	}

	iface = STAILQ_FIRST(&config->interfaces);

	conf_phc_index = config_get_int(config, interface_name(iface), "phc_index");

	/* determine PHC Clock index */
	if (config_get_int(config, NULL, "free_running")) {
		phc_index = -1;
	} else if (timestamping == TS_SOFTWARE || timestamping == TS_LEGACY_HW) {
		phc_index = -1;
	} else if (phc_device) {
		if (1 != sscanf(phc_device, "/dev/ptp%d", &phc_index)) {
			phc_index = -1;
		}
	} else if (conf_phc_index >= 0) {
		phc_index = conf_phc_index;
	} else if (interface_tsinfo_valid(iface)) {
		phc_index = interface_phc_index(iface);
	} else {
		pr_err("PTP device not specified and automatic determination"
		       " is not supported. Please specify PTP device.");
		return NULL;
	}
	if (phc_index >= 0) {
		pr_info("selected /dev/ptp%d as PTP clock", phc_index);
	}

	if (strcmp(config_get_string(config, NULL, "clockIdentity"),
		   "000000.0000.000000") == 0) {
		if (generate_clock_identity(&c->dds.clockIdentity,
					    interface_name(iface))) {
			pr_err("failed to generate a clock identity");
			return NULL;
		}
	} else {
		if (str2cid(config_get_string(config, NULL, "clockIdentity"),
					      &c->dds.clockIdentity)) {
			pr_err("failed to set clock identity");
			return NULL;
		}
	}

	/* Configure the UDS. */

	uds_ifname = config_get_string(config, NULL, "uds_address");
	c->uds_rw_if = interface_create(uds_ifname, NULL);
	if (config_set_section_int(config, interface_name(c->uds_rw_if),
				   "announceReceiptTimeout", 0)) {
		return NULL;
	}
	if (config_set_section_int(config, interface_name(c->uds_rw_if),
				    "delay_mechanism", DM_AUTO)) {
		return NULL;
	}
	if (config_set_section_int(config, interface_name(c->uds_rw_if),
				    "network_transport", TRANS_UDS)) {
		return NULL;
	}
	if (config_set_section_int(config, interface_name(c->uds_rw_if),
				   "delay_filter_length", 1)) {
		return NULL;
	}

	uds_ifname = config_get_string(config, NULL, "uds_ro_address");
	c->uds_ro_if = interface_create(uds_ifname, NULL);
	if (config_set_section_int(config, interface_name(c->uds_ro_if),
				   "announceReceiptTimeout", 0)) {
		return NULL;
	}
	if (config_set_section_int(config, interface_name(c->uds_ro_if),
				   "delay_mechanism", DM_AUTO)) {
		return NULL;
	}
	if (config_set_section_int(config, interface_name(c->uds_ro_if),
				   "network_transport", TRANS_UDS)) {
		return NULL;
	}
	if (config_set_section_int(config, interface_name(c->uds_ro_if),
				   "delay_filter_length", 1)) {
		return NULL;
	}

	c->config = config;
	c->free_running = config_get_int(config, NULL, "free_running");
	c->freq_est_interval = config_get_int(config, NULL, "freq_est_interval");
	c->local_sync_uncertain = SYNC_UNCERTAIN_DONTCARE;
	c->write_phase_mode = config_get_int(config, NULL, "write_phase_mode");
	c->grand_master_capable = config_get_int(config, NULL, "gmCapable");
	c->kernel_leap = config_get_int(config, NULL, "kernel_leap");
	c->utc_offset = config_get_int(config, NULL, "utc_offset");
	c->time_source = config_get_int(config, NULL, "timeSource");
	c->step_window = config_get_int(config, NULL, "step_window");

	if (c->free_running) {
		c->clkid = CLOCK_INVALID;
		if (timestamping == TS_SOFTWARE || timestamping == TS_LEGACY_HW) {
			c->utc_timescale = 1;
		}
	} else if (phc_index >= 0) {
		snprintf(phc, sizeof(phc), "/dev/ptp%d", phc_index);
		c->clkid = phc_open(phc);
		if (c->clkid == CLOCK_INVALID) {
			pr_err("Failed to open %s: %m", phc);
			return NULL;
		}
		max_adj = phc_max_adj(c->clkid);
		if (!max_adj) {
			pr_err("clock is not adjustable");
			return NULL;
		}
		clockadj_init(c->clkid);
	} else if (phc_device) {
		c->clkid = phc_open(phc_device);
		if (c->clkid == CLOCK_INVALID) {
			pr_err("Failed to open %s: %m", phc_device);
			return NULL;
		}
		max_adj = clockadj_max_freq(c->clkid);
		clockadj_init(c->clkid);
	} else {
		c->clkid = CLOCK_REALTIME;
		c->utc_timescale = 1;
		clockadj_init(c->clkid);
		max_adj = sysclk_max_freq();
		sysclk_set_leap(0);
	}
	c->utc_offset_set = 0;
	c->leap_set = 0;
	c->time_flags = c->utc_timescale ? 0 : PTP_TIMESCALE;

	if (c->clkid != CLOCK_INVALID) {
		fadj = clockadj_get_freq(c->clkid);
		/* Disable write phase mode if not implemented by driver */
		if (c->write_phase_mode && !phc_has_writephase(c->clkid)) {
			pr_err("clock does not support write phase mode");
			return NULL;
		}
	}
	c->servo = servo_create(c->config, servo, -fadj, max_adj, sw_ts);
	if (!c->servo) {
		pr_err("Failed to create clock servo");
		return NULL;
	}
	c->servo_state = SERVO_UNLOCKED;
	c->servo_type = servo;
	if (config_get_int(config, NULL, "dataset_comparison") == DS_CMP_G8275) {
		c->dscmp = telecom_dscmp;
	} else {
		c->dscmp = dscmp;
	}
	c->tsproc = tsproc_create(config_get_int(config, NULL, "tsproc_mode"),
				  config_get_int(config, NULL, "delay_filter"),
				  config_get_int(config, NULL, "delay_filter_length"));
	if (!c->tsproc) {
		pr_err("Failed to create time stamp processor");
		return NULL;
	}
	c->initial_delay = dbl_tmv(config_get_int(config, NULL, "initial_delay"));
	if (!tmv_is_zero(c->initial_delay)) {
		tsproc_set_delay(c->tsproc, c->initial_delay);
	}
	c->path_delay = c->initial_delay;
	c->master_local_rr = 1.0;
	c->nrr = 1.0;
	c->stats_interval = config_get_int(config, NULL, "summary_interval");
	c->stats.offset = stats_create();
	c->stats.freq = stats_create();
	c->stats.delay = stats_create();
	if (!c->stats.offset || !c->stats.freq || !c->stats.delay) {
		pr_err("failed to create stats");
		return NULL;
	}
	sfl = config_get_int(config, NULL, "sanity_freq_limit");
	if (sfl) {
		c->sanity_check = clockcheck_create(sfl);
		if (!c->sanity_check) {
			pr_err("Failed to create clock sanity check");
			return NULL;
		}
	}

	/* Initialize the parentDS. */
	clock_update_grandmaster(c);
	c->dad.pds.parentStats                           = 0;
	c->dad.pds.observedParentOffsetScaledLogVariance = 0xffff;
	c->dad.pds.observedParentClockPhaseChangeRate    = 0x7fffffff;
	c->dad.ptl = c->ptl;

	for (i = 0; i < MAX_TIME_ZONES; i++) {
		c->tz[i].display_name.max_symbols = MAX_TZ_DISPLAY_NAME;
	}

	clock_sync_interval(c, 0);

	LIST_INIT(&c->subscribers);
	LIST_INIT(&c->ports);
	c->last_port_number = 0;

	if (clock_resize_pollfd(c, 0)) {
		pr_err("failed to allocate pollfd");
		return NULL;
	}

	/* Create the UDS interfaces. */

	c->uds_rw_port = port_open(phc_device, phc_index, timestamping, 0,
				   c->uds_rw_if, c);
	if (!c->uds_rw_port) {
		pr_err("failed to open the UDS-RW port");
		return NULL;
	}
	c->uds_ro_port = port_open(phc_device, phc_index, timestamping, 0,
				   c->uds_ro_if, c);
	if (!c->uds_ro_port) {
		pr_err("failed to open the UDS-RO port");
		return NULL;
	}
	clock_fda_changed(c);

	c->slave_event_monitor = monitor_create(config, c->uds_rw_port);
	if (!c->slave_event_monitor) {
		pr_err("failed to create slave event monitor");
		return NULL;
	}

	/* Create the ports. */
	STAILQ_FOREACH(iface, &config->interfaces, list) {
		if (clock_add_port(c, phc_device, phc_index, timestamping, iface)) {
			pr_err("failed to open port %s", interface_name(iface));
			return NULL;
		}
	}

	c->dds.numberPorts = c->nports;

	LIST_FOREACH(p, &c->ports, list) {
		port_dispatch(p, EV_INITIALIZE, 0);
	}
	port_dispatch(c->uds_rw_port, EV_INITIALIZE, 0);
	port_dispatch(c->uds_ro_port, EV_INITIALIZE, 0);

	return c;
}

struct dataset *clock_best_foreign(struct clock *c)
{
	return c->best ? &c->best->dataset : NULL;
}

struct port *clock_best_port(struct clock *c)
{
	return c->best ? c->best->port : NULL;
}

struct dataset *clock_default_ds(struct clock *c)
{
	struct dataset *out = &c->default_dataset;
	struct defaultDS *in = &c->dds;

	out->priority1              = in->priority1;
	out->identity               = in->clockIdentity;
	out->quality                = in->clockQuality;
	out->priority2              = in->priority2;
	out->stepsRemoved           = 0;
	out->sender.clockIdentity   = in->clockIdentity;
	out->sender.portNumber      = 0;
	out->receiver.clockIdentity = in->clockIdentity;
	out->receiver.portNumber    = 0;

	return out;
}

UInteger8 clock_domain_number(struct clock *c)
{
	return c->dds.domainNumber;
}

struct port *clock_first_port(struct clock *c)
{
	return LIST_FIRST(&c->ports);
}

void clock_follow_up_info(struct clock *c, struct follow_up_info_tlv *f)
{
	c->status.cumulativeScaledRateOffset = f->cumulativeScaledRateOffset;
	c->status.scaledLastGmPhaseChange = f->scaledLastGmPhaseChange;
	c->status.gmTimeBaseIndicator = f->gmTimeBaseIndicator;
	memcpy(&c->status.lastGmPhaseChange, &f->lastGmPhaseChange,
	       sizeof(c->status.lastGmPhaseChange));
}

int clock_free_running(struct clock *c)
{
	return c->free_running ? 1 : 0;
}

int clock_gm_capable(struct clock *c)
{
	return c->grand_master_capable;
}

struct ClockIdentity clock_identity(struct clock *c)
{
	return c->dds.clockIdentity;
}

static int clock_resize_pollfd(struct clock *c, int new_nports)
{
	struct pollfd *new_pollfd;

	/* Need to allocate two whole extra blocks of fds for UDS ports. */
	new_pollfd = realloc(c->pollfd,
			     (new_nports + 2) * N_CLOCK_PFD *
			     sizeof(struct pollfd));
	if (!new_pollfd) {
		return -1;
	}
	c->pollfd = new_pollfd;
	return 0;
}

static void clock_fill_pollfd(struct pollfd *dest, struct port *p)
{
	struct fdarray *fda;
	int i;

	fda = port_fda(p);
	for (i = 0; i < N_POLLFD; i++) {
		dest[i].fd = fda->fd[i];
		dest[i].events = POLLIN|POLLPRI;
	}
	dest[i].fd = port_fault_fd(p);
	dest[i].events = POLLIN|POLLPRI;
}

static void clock_check_pollfd(struct clock *c)
{
	struct port *p;
	struct pollfd *dest = c->pollfd;

	if (c->pollfd_valid) {
		return;
	}
	LIST_FOREACH(p, &c->ports, list) {
		clock_fill_pollfd(dest, p);
		dest += N_CLOCK_PFD;
	}
	clock_fill_pollfd(dest, c->uds_rw_port);
	dest += N_CLOCK_PFD;
	clock_fill_pollfd(dest, c->uds_ro_port);
	c->pollfd_valid = 1;
}

void clock_fda_changed(struct clock *c)
{
	c->pollfd_valid = 0;
}

static int clock_do_forward_mgmt(struct clock *c,
				 struct port *in, struct port *out,
				 struct ptp_message *msg, int *pre_sent)
{
	if (in == out || !forwarding(c, out))
		return 0;

	/* Don't forward any requests to the UDS-RW port
	   (the UDS-RO port doesn't allow any forwarding). */
	if (out == c->uds_rw_port) {
		switch (management_action(msg)) {
		case GET:
		case SET:
		case COMMAND:
			return 0;
		}
	}

	if (!*pre_sent) {
		/* delay calling msg_pre_send until
		 * actually forwarding */
		msg_pre_send(msg);
		sad_update_auth_tlv(clock_config(c), msg);
		*pre_sent = 1;
	}
	return port_forward(out, msg);
}

static void clock_forward_mgmt_msg(struct clock *c, struct port *p, struct ptp_message *msg)
{
	struct port *piter;
	int pdulen = 0, msg_ready = 0;

	if (forwarding(c, p) && msg->management.boundaryHops) {
		pdulen = msg->header.messageLength;
		msg->management.boundaryHops--;
		LIST_FOREACH(piter, &c->ports, list) {
			if (clock_do_forward_mgmt(c, p, piter, msg, &msg_ready))
				pr_err("%s: management forward failed",
				       port_log_name(piter));
		}
		if (clock_do_forward_mgmt(c, p, c->uds_rw_port, msg, &msg_ready))
			pr_debug("uds port: management forward failed");
		if (msg_ready) {
			msg_post_recv(msg, pdulen);
			msg->management.boundaryHops++;
		}
	}
}

tmv_t clock_ingress_time(struct clock *c)
{
	return c->ingress_ts;
}

int clock_manage(struct clock *c, struct port *p, struct ptp_message *msg)
{
	int changed = 0, res, answers;
	struct port *piter;
	struct tlv_extra *extra;
	struct management_tlv *mgt;
	struct ClockIdentity *tcid, wildcard = {
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	};

	/* Forward this message out all eligible ports. */
	clock_forward_mgmt_msg(c, p, msg);

	/* Apply this message to the local clock and ports. */
	tcid = &msg->management.targetPortIdentity.clockIdentity;
	if (!cid_eq(tcid, &wildcard) && !cid_eq(tcid, &c->dds.clockIdentity)) {
		return changed;
	}
	switch (msg_tlv_count(msg)) {
	case 1:
		break;
	case 2:
		extra = TAILQ_LAST(&msg->tlv_list, tlv_list);
		if (extra->tlv->type == TLV_AUTHENTICATION) {
			break;
		}
	default:
		return changed;
	}
	mgt = (struct management_tlv *) msg->management.suffix;

	/*
	  The correct length according to the management ID is checked
	  in tlv.c, but management TLVs with empty bodies are also
	  received successfully to support GETs and CMDs. At this
	  point the TLV either has the correct length or length 2.
	*/
	switch (management_action(msg)) {
	case GET:
		if (clock_management_get_response(c, p, mgt->id, msg))
			return changed;
		break;
	case SET:
		if (mgt->length == 2 && mgt->id != MID_NULL_MANAGEMENT) {
			clock_management_send_error(p, msg, MID_WRONG_LENGTH);
			return changed;
		}
		if (p != c->uds_rw_port) {
			/* Sorry, only allowed on the UDS-RW port. */
			clock_management_send_error(p, msg, MID_NOT_SUPPORTED);
			return changed;
		}
		if (clock_management_set(c, p, mgt->id, msg, &changed))
			return changed;
		break;
	case COMMAND:
		if (p != c->uds_rw_port) {
			/* Sorry, only allowed on the UDS-RW port. */
			clock_management_send_error(p, msg, MID_NOT_SUPPORTED);
			return changed;
		}
		break;
	default:
		return changed;
	}

	switch (mgt->id) {
	case MID_PORT_PROPERTIES_NP:
	case MID_PORT_HWCLOCK_NP:
		if (p != c->uds_rw_port) {
			/* Only the UDS-RW port allowed. */
			clock_management_send_error(p, msg, MID_NOT_SUPPORTED);
			return 0;
		}
	}

	switch (mgt->id) {
	case MID_USER_DESCRIPTION:
	case MID_SAVE_IN_NON_VOLATILE_STORAGE:
	case MID_RESET_NON_VOLATILE_STORAGE:
	case MID_INITIALIZE:
	case MID_FAULT_LOG:
	case MID_FAULT_LOG_RESET:
	case MID_DEFAULT_DATA_SET:
	case MID_CURRENT_DATA_SET:
	case MID_PARENT_DATA_SET:
	case MID_TIME_PROPERTIES_DATA_SET:
	case MID_PRIORITY1:
	case MID_PRIORITY2:
	case MID_DOMAIN:
	case MID_SLAVE_ONLY:
	case MID_TIME:
	case MID_CLOCK_ACCURACY:
	case MID_UTC_PROPERTIES:
	case MID_TRACEABILITY_PROPERTIES:
	case MID_TIMESCALE_PROPERTIES:
	case MID_PATH_TRACE_LIST:
	case MID_PATH_TRACE_ENABLE:
	case MID_GRANDMASTER_CLUSTER_TABLE:
	case MID_ACCEPTABLE_MASTER_TABLE:
	case MID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE:
	case MID_ALTERNATE_TIME_OFFSET_MAX_KEY:
	case MID_TRANSPARENT_CLOCK_DEFAULT_DATA_SET:
	case MID_PRIMARY_DOMAIN:
	case MID_TIME_STATUS_NP:
	case MID_GRANDMASTER_SETTINGS_NP:
	case MID_SUBSCRIBE_EVENTS_NP:
	case MID_SYNCHRONIZATION_UNCERTAIN_NP:
		clock_management_send_error(p, msg, MID_NOT_SUPPORTED);
		break;
	default:
		answers = 0;
		LIST_FOREACH(piter, &c->ports, list) {
			res = port_manage(piter, p, msg);
			if (res < 0)
				return changed;
			if (res > 0)
				answers++;
		}
		if (!answers) {
			/* IEEE 1588 Interpretation #21 suggests to use
			 * MID_WRONG_VALUE for ports that do not exist */
			clock_management_send_error(p, msg, MID_WRONG_VALUE);
		}
		break;
	}
	return changed;
}

void clock_notify_event(struct clock *c, enum notification event)
{
	struct port *uds = c->uds_rw_port;
	struct PortIdentity pid;
	struct ptp_message *msg;
	int id;

	/* A notification may come before UDS is created */
	if (!uds)
		return;

	pid = port_identity(uds);

	switch (event) {
	case NOTIFY_TIME_SYNC:
		id = MID_TIME_STATUS_NP;
		break;
	case NOTIFY_PARENT_DATA_SET:
		id = MID_PARENT_DATA_SET;
		break;
	default:
		return;
	}
	/* targetPortIdentity and sequenceId will be filled by
	 * clock_send_notification */
	msg = port_management_notify(pid, uds);
	if (!msg)
		return;
	if (!clock_management_fill_response(c, NULL, NULL, msg, id))
		goto err;
	if (msg_pre_send(msg))
		goto err;
	clock_send_notification(c, msg, event);
err:
	msg_put(msg);
}

struct parent_ds *clock_parent_ds(struct clock *c)
{
	return &c->dad;
}

struct PortIdentity clock_parent_identity(struct clock *c)
{
	return c->dad.pds.parentPortIdentity;
}

void clock_set_sde(struct clock *c, int sde)
{
	c->sde = sde;
}

int clock_poll(struct clock *c)
{
	int cnt, i;
	enum port_state prior_state;
	enum fsm_event event;
	struct pollfd *cur;
	struct port *p;

	clock_check_pollfd(c);
	cnt = poll(c->pollfd, (c->nports + 2) * N_CLOCK_PFD, -1);
	if (cnt < 0) {
		if (EINTR == errno) {
			return 0;
		} else {
			pr_emerg("poll failed");
			return -1;
		}
	} else if (!cnt) {
		return 0;
	}

	cur = c->pollfd;

	LIST_FOREACH(p, &c->ports, list) {
		/* Let the ports handle their events. */
		for (i = 0; i < N_POLLFD; i++) {
			if (cur[i].revents & (POLLIN|POLLPRI|POLLERR)) {
				prior_state = port_state(p);
				if (cur[i].revents & POLLERR) {
					int error = sk_get_error(cur[i].fd);
					pr_err("%s: error on fda[%d]: %s",
					       port_log_name(p), i,
					       strerror(error));
					event = EV_FAULT_DETECTED;
				} else {
					event = port_event(p, i);
				}
				if (EV_STATE_DECISION_EVENT == event) {
					c->sde = 1;
				}
				if (EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES == event) {
					c->sde = 1;
				}
				port_dispatch(p, event, 0);
				/* Clear any fault after a little while. */
				if ((PS_FAULTY == port_state(p)) && (prior_state != PS_FAULTY)) {
					clock_fault_timeout(p, 1);
					break;
				}
			}
		}

		/*
		 * When the fault timer expires we clear the fault,
		 * but only if the link is up.
		 */
		if (cur[N_POLLFD].revents & (POLLIN|POLLPRI)) {
			clock_fault_timeout(p, 0);
			if (port_link_status_get(p)) {
				port_dispatch(p, EV_FAULT_CLEARED, 0);
			}
		}

		cur += N_CLOCK_PFD;
	}

	/* Check the UDS ports. */
	for (i = 0; i < N_POLLFD; i++) {
		if (cur[i].revents & (POLLIN|POLLPRI)) {
			event = port_event(c->uds_rw_port, i);
			if (EV_STATE_DECISION_EVENT == event) {
				c->sde = 1;
			}
		}
	}
	cur += N_CLOCK_PFD;
	for (i = 0; i < N_POLLFD; i++) {
		if (cur[i].revents & (POLLIN|POLLPRI)) {
			event = port_event(c->uds_ro_port, i);
			/* sde is not expected on the UDS-RO port */
		}
	}

	if (c->sde) {
		handle_state_decision_event(c);
		c->sde = 0;
	}
	clock_prune_subscriptions(c);
	return 0;
}

void clock_path_delay(struct clock *c, tmv_t req, tmv_t rx)
{
	tsproc_up_ts(c->tsproc, req, rx);

	if (tsproc_update_delay(c->tsproc, &c->path_delay))
		return;

	c->cur.meanPathDelay = tmv_to_TimeInterval(c->path_delay);

	if (c->stats.delay)
		stats_add_value(c->stats.delay, tmv_dbl(c->path_delay));
}

void clock_peer_delay(struct clock *c, tmv_t ppd, tmv_t req, tmv_t rx,
		      double nrr)
{
	c->path_delay = ppd;
	c->nrr = nrr;

	tsproc_set_delay(c->tsproc, ppd);
	tsproc_up_ts(c->tsproc, req, rx);

	if (c->stats.delay)
		stats_add_value(c->stats.delay, tmv_dbl(ppd));
}

struct monitor *clock_slave_monitor(struct clock *c)
{
	return c->slave_event_monitor;
}

int clock_slave_only(struct clock *c)
{
	return c->dds.flags & DDS_SLAVE_ONLY;
}

UInteger8 clock_max_steps_removed(struct clock *c)
{
	return c->max_steps_removed;
}

UInteger8 clock_get_clock_class_threshold(struct clock *c)
{
	return c->clock_class_threshold;
}

UInteger16 clock_steps_removed(struct clock *c)
{
	return c->cur.stepsRemoved;
}

struct tsproc *clock_get_tsproc(struct clock *c)
{
	return c->tsproc;
}

int clock_switch_phc(struct clock *c, int phc_index)
{
	struct servo *servo;
	clockid_t clkid;
	char phc[32];
	double fadj;
	int max_adj;

	snprintf(phc, sizeof(phc), "/dev/ptp%d", phc_index);
	clkid = phc_open(phc);
	if (clkid == CLOCK_INVALID) {
		pr_err("Switching PHC, failed to open %s: %m", phc);
		return -1;
	}
	max_adj = phc_max_adj(clkid);
	if (!max_adj) {
		pr_err("Switching PHC, clock is not adjustable");
		phc_close(clkid);
		return -1;
	}
	fadj = clockadj_get_freq(clkid);
	servo = servo_create(c->config, c->servo_type, -fadj, max_adj, 0);
	if (!servo) {
		pr_err("Switching PHC, failed to create clock servo");
		phc_close(clkid);
		return -1;
	}
	phc_close(c->clkid);
	servo_destroy(c->servo);
	c->clkid = clkid;
	c->servo = servo;
	c->servo_state = SERVO_UNLOCKED;

	pr_info("Switched to /dev/ptp%d as PTP clock", phc_index);

	return 0;
}

static void clock_step_window(struct clock *c)
{
	if (!c->step_window) {
		return;
	}
	c->step_window_counter = c->step_window;
}

static int clock_synchronize_locked(struct clock *c, double adj)
{
	if (c->sanity_check) {
		clockcheck_freq(c->sanity_check, clockadj_get_freq(c->clkid));
	}
	if (clockadj_set_freq(c->clkid, -adj)) {
		return -1;
	}
	if (c->clkid == CLOCK_REALTIME) {
		sysclk_set_sync();
	}
	if (c->sanity_check) {
		clockcheck_set_freq(c->sanity_check, -adj);
	}
	return 0;
}

enum servo_state clock_synchronize(struct clock *c, tmv_t ingress, tmv_t origin)
{
	enum servo_state state = SERVO_UNLOCKED;
	double adj, weight;
	int64_t offset;

	if (c->step_window_counter) {
		c->step_window_counter--;
		pr_debug("skip sync after jump %d/%d",
			 c->step_window - c->step_window_counter,
			 c->step_window);
		return c->servo_state;
	}

	c->ingress_ts = ingress;

	tsproc_down_ts(c->tsproc, origin, ingress);

	if (tsproc_update_offset(c->tsproc, &c->master_offset, &weight)) {
		if (c->free_running) {
			return clock_no_adjust(c, ingress, origin);
		} else {
			return state;
		}
	}

	if (clock_utc_correct(c, ingress)) {
		return c->servo_state;
	}

	c->cur.offsetFromMaster = tmv_to_TimeInterval(c->master_offset);

	if (c->free_running) {
		state = clock_no_adjust(c, ingress, origin);
		clock_notify_event(c, NOTIFY_TIME_SYNC);
		return state;
	}

	offset = tmv_to_nanoseconds(c->master_offset);
	adj = servo_sample(c->servo, offset, tmv_to_nanoseconds(ingress),
			   weight, &state);
	c->servo_state = state;

	tsproc_set_clock_rate_ratio(c->tsproc, clock_rate_ratio(c));

	switch (state) {
	case SERVO_UNLOCKED:
		break;
	case SERVO_JUMP:
		if (clockadj_set_freq(c->clkid, -adj)) {
			goto servo_unlock;
		}
		if (clockadj_step(c->clkid, -tmv_to_nanoseconds(c->master_offset))) {
			goto servo_unlock;
		}
		c->ingress_ts = tmv_zero();
		if (c->sanity_check) {
			clockcheck_set_freq(c->sanity_check, -adj);
			clockcheck_step(c->sanity_check,
					-tmv_to_nanoseconds(c->master_offset));
		}
		tsproc_reset(c->tsproc, 0);
		clock_step_window(c);
		break;
	case SERVO_LOCKED:
		if (clock_synchronize_locked(c, adj)) {
			goto servo_unlock;
		}
		break;
	case SERVO_LOCKED_STABLE:
		if (c->write_phase_mode) {
			if (clockadj_set_phase(c->clkid, -offset)) {
				goto servo_unlock;
			}
			adj = 0;
		} else {
			if (clock_synchronize_locked(c, adj)) {
				goto servo_unlock;
			}
		}
		break;
	}

	if (c->stats.max_count > 1) {
		clock_stats_update(&c->stats, tmv_dbl(c->master_offset), adj);
	} else {
		pr_info("master offset %10" PRId64 " s%d freq %+7.0f "
			"path delay %9" PRId64,
			tmv_to_nanoseconds(c->master_offset), state, adj,
			tmv_to_nanoseconds(c->path_delay));
	}

	clock_notify_event(c, NOTIFY_TIME_SYNC);

	return state;

servo_unlock:
	servo_reset(c->servo);
	c->servo_state = SERVO_UNLOCKED;
	return SERVO_UNLOCKED;
}

void clock_sync_interval(struct clock *c, int n)
{
	int shift;

	shift = c->freq_est_interval - n;
	if (shift < 0)
		shift = 0;
	else if (shift >= sizeof(int) * 8) {
		shift = sizeof(int) * 8 - 1;
		pr_warning("freq_est_interval is too long");
	}
	c->fest.max_count = (1U << shift);

	/* In free-running mode stats accumulate once per freq_est_interval */
	if (c->free_running)
		shift = c->stats_interval - n - shift;
	else
		shift = c->stats_interval - n;

	if (shift < 0)
		shift = 0;
	else if (shift >= sizeof(int) * 8) {
		shift = sizeof(int) * 8 - 1;
		pr_warning("summary_interval is too long");
	}
	c->stats.max_count = (1U << shift);

	servo_sync_interval(c->servo, n < 0 ? 1.0 / (1 << -n) : 1 << n);
}

void clock_update_leap_status(struct clock *c)
{
	struct timespec ts;
	int leap;

	if (c->tds.flags & LEAP_61) {
		leap = 1;
	} else if (c->tds.flags & LEAP_59) {
		leap = -1;
	} else {
		leap = 0;
	}

	/* Don't do anything if not a grandmaster with a leap flag set. */
	if (c->cur.stepsRemoved > 0 || leap == 0) {
		return;
	}

	clock_gettime(c->clkid, &ts);
	if (c->time_flags & PTP_TIMESCALE) {
		ts.tv_sec -= c->utc_offset;
	}

	/* Wait until the leap second has passed. */
	if (leap_second_status(tmv_to_nanoseconds(timespec_to_tmv(ts)),
			       leap, &leap, &c->utc_offset)) {
		return;
	}

	c->time_flags &= ~(LEAP_61 | LEAP_59);
	clock_update_grandmaster(c);
}

struct timePropertiesDS clock_time_properties(struct clock *c)
{
	struct timePropertiesDS tds = c->tds;

	switch (c->local_sync_uncertain) {
	case SYNC_UNCERTAIN_DONTCARE:
		tds.flags &= ~SYNC_UNCERTAIN;
		break;
	case SYNC_UNCERTAIN_FALSE:
		/* Pass the upstream value, if any. */
		break;
	case SYNC_UNCERTAIN_TRUE:
		tds.flags |= SYNC_UNCERTAIN;
		break;
	}
	return tds;
}

void clock_update_time_properties(struct clock *c, struct timePropertiesDS tds)
{
	if ((tds.flags ^ c->tds.flags) & (LEAP_61 | LEAP_59)) {
		pr_info("updating time properties to %s leap second",
			tds.flags & (LEAP_61 | LEAP_59) ?
			(tds.flags & LEAP_61 ? "insert" : "delete") : "no");
	}
	if ((tds.flags & UTC_OFF_VALID && tds.flags & TIME_TRACEABLE &&
	     tds.currentUtcOffset != c->utc_offset) ||
	    tds.currentUtcOffset > c->utc_offset) {
		pr_info("updating UTC offset to %d", tds.currentUtcOffset);
		c->utc_offset = tds.currentUtcOffset;
	}

	c->tds = tds;
}

static void handle_state_decision_event(struct clock *c)
{
	struct foreign_clock *best = NULL, *fc;
	struct ClockIdentity best_id;
	struct port *piter;
	int fresh_best = 0;

	LIST_FOREACH(piter, &c->ports, list) {
		fc = port_compute_best(piter);
		if (!fc)
			continue;
		if (!best || c->dscmp(&fc->dataset, &best->dataset) > 0)
			best = fc;
	}

	if (best) {
		best_id = best->dataset.identity;
	} else {
		best_id = c->dds.clockIdentity;
	}

	if (!cid_eq(&best_id, &c->best_id) || best != c->best) {
		clock_freq_est_reset(c);
		if (c->sanity_check)
			clockcheck_reset(c->sanity_check);
		tsproc_reset(c->tsproc, 1);
		if (!tmv_is_zero(c->initial_delay) || (best &&
			port_delay_mechanism(best->port) == DM_NO_MECHANISM)) {
			tsproc_set_delay(c->tsproc, c->initial_delay);
		}
		c->ingress_ts = tmv_zero();
		c->path_delay = c->initial_delay;
		c->master_local_rr = 1.0;
		c->nrr = 1.0;
		fresh_best = 1;
		if (cid_eq(&best_id, &c->dds.clockIdentity)) {
			pr_notice("selected local clock %s as best master",
					cid2str(&best_id));
		} else {
			pr_notice("selected best master clock %s",
					cid2str(&best_id));
		}
	}

	c->best = best;
	c->best_id = best_id;

	LIST_FOREACH(piter, &c->ports, list) {
		enum port_state ps;
		enum fsm_event event;
		ps = bmc_state_decision(c, piter, c->dscmp);
		switch (ps) {
		case PS_LISTENING:
			event = EV_NONE;
			break;
		case PS_GRAND_MASTER:
			pr_notice("%s: assuming the grand master role",
				  port_log_name(piter));
			clock_update_grandmaster(c);
			event = EV_RS_GRAND_MASTER;
			break;
		case PS_MASTER:
			event = EV_RS_MASTER;
			break;
		case PS_PASSIVE:
			event = EV_RS_PASSIVE;
			break;
		case PS_SLAVE:
			clock_update_slave(c);
			event = EV_RS_SLAVE;
			break;
		default:
			event = EV_FAULT_DETECTED;
			break;
		}
		port_dispatch(piter, event, fresh_best);
	}

	LIST_FOREACH(piter, &c->ports, list) {
		port_update_unicast_state(piter);
	}
}

struct clock_description *clock_description(struct clock *c)
{
	return &c->desc;
}

enum clock_type clock_type(struct clock *c)
{
	return c->type;
}

void clock_check_ts(struct clock *c, uint64_t ts)
{
	if (c->sanity_check && clockcheck_sample(c->sanity_check, ts)) {
		servo_reset(c->servo);
	}
}

double clock_rate_ratio(struct clock *c)
{
	if (c->free_running) {
		return c->master_local_rr;
	}
	return servo_rate_ratio(c->servo);
}

struct servo *clock_servo(struct clock *c)
{
	return c->servo;
}

enum servo_state clock_servo_state(struct clock *c)
{
	return c->servo_state;
}
