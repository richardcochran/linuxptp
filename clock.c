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
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bmc.h"
#include "clock.h"
#include "foreign.h"
#include "mave.h"
#include "missing.h"
#include "msg.h"
#include "phc.h"
#include "port.h"
#include "servo.h"
#include "print.h"
#include "tlv.h"
#include "uds.h"
#include "util.h"

#define CLK_N_PORTS (MAX_PORTS + 1) /* plus one for the UDS interface */
#define FAULT_RESET_SECONDS 15
#define N_CLOCK_PFD (N_POLLFD + 1) /* one extra per port, for the fault timer */
#define MAVE_LENGTH 10
#define POW2_41 ((double)(1ULL << 41))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct freq_estimator {
	tmv_t origin1;
	tmv_t ingress1;
	int max_count;
	int count;
};

struct clock {
	clockid_t clkid;
	struct servo *servo;
	struct defaultDS dds;
	struct dataset default_dataset;
	struct currentDS cur;
	struct parentDS dad;
	struct timePropertiesDS tds;
	struct ClockIdentity ptl[PATH_TRACE_MAX];
	struct foreign_clock *best;
	struct ClockIdentity best_id;
	struct port *port[CLK_N_PORTS];
	struct pollfd pollfd[CLK_N_PORTS*N_CLOCK_PFD];
	int fault_fd[CLK_N_PORTS];
	time_t fault_timeout;
	int nports; /* does not include the UDS port */
	int utc_timescale;
	tmv_t master_offset;
	tmv_t path_delay;
	struct mave *avg_delay;
	struct freq_estimator fest;
	struct time_status_np status;
	double nrr;
	tmv_t c1;
	tmv_t c2;
	tmv_t t1;
	tmv_t t2;
};

struct clock the_clock;

static void handle_state_decision_event(struct clock *c);

static int cid_eq(struct ClockIdentity *a, struct ClockIdentity *b)
{
	return 0 == memcmp(a, b, sizeof(*a));
}

void clock_destroy(struct clock *c)
{
	int i;
	for (i = 0; i < c->nports; i++) {
		port_close(c->port[i]);
		close(c->fault_fd[i]);
	}
	port_close(c->port[i]); /*uds*/
	if (c->clkid != CLOCK_REALTIME) {
		phc_close(c->clkid);
	}
	servo_destroy(c->servo);
	mave_destroy(c->avg_delay);
	memset(c, 0, sizeof(*c));
	msg_cleanup();
}

static int clock_fault_timeout(struct clock *c, int index, int set)
{
	struct itimerspec tmo = {
		{0, 0}, {0, 0}
	};
	if (set) {
		pr_debug("waiting %d seconds to clear fault on port %d",
			 c->fault_timeout, index);
		tmo.it_value.tv_sec = c->fault_timeout;
	} else {
		pr_debug("clearing fault on port %d", index);
	}
	return timerfd_settime(c->fault_fd[index], 0, &tmo, NULL);
}

static void clock_freq_est_reset(struct clock *c)
{
	c->fest.origin1 = tmv_zero();
	c->fest.ingress1 = tmv_zero();
	c->fest.count = 0;
};

static int clock_management_response(struct clock *c, struct port *p, int id,
				     struct ptp_message *req)
{
	int datalen = 0, err, pdulen, respond = 0;
	struct management_tlv *tlv;
	struct ptp_message *rsp;
	struct time_status_np *tsn;
	struct PortIdentity pid = port_identity(p);

	rsp = port_management_reply(pid, p, req);
	if (!rsp) {
		return 0;
	}
	tlv = (struct management_tlv *) rsp->management.suffix;
	tlv->type = TLV_MANAGEMENT;
	tlv->id = id;

	switch (id) {
	case CURRENT_DATA_SET:
		memcpy(tlv->data, &c->cur, sizeof(c->cur));
		datalen = sizeof(c->cur);
		respond = 1;
		break;
	case TIME_STATUS_NP:
		tsn = (struct time_status_np *) tlv->data;
		tsn->master_offset = c->master_offset;
		tsn->ingress_time = tmv_to_nanoseconds(c->t2);
		tsn->cumulativeScaledRateOffset =
			(UInteger32) (c->status.cumulativeScaledRateOffset +
				      c->nrr * POW2_41 - POW2_41);
		tsn->scaledLastGmPhaseChange = c->status.scaledLastGmPhaseChange;
		tsn->gmTimeBaseIndicator = c->status.gmTimeBaseIndicator;
		tsn->lastGmPhaseChange = c->status.lastGmPhaseChange;
		if (cid_eq(&c->dad.grandmasterIdentity, &c->dds.clockIdentity))
			tsn->gmPresent = 0;
		else
			tsn->gmPresent = 1;
		tsn->gmIdentity = c->dad.grandmasterIdentity;
		datalen = sizeof(*tsn);
		respond = 1;
		break;
	}
	if (respond) {
		tlv->length = sizeof(tlv->id) + datalen;
		pdulen = rsp->header.messageLength + sizeof(*tlv) + datalen;
		rsp->header.messageLength = pdulen;
		rsp->tlv_count = 1;
		err = msg_pre_send(rsp);
		if (err) {
			goto out;
		}
		err = port_forward(p, rsp, pdulen);
	}
out:
	msg_put(rsp);
	return respond ? 1 : 0;
}

static int clock_master_lost(struct clock *c)
{
	int i;
	for (i = 0; i < c->nports; i++) {
		if (PS_SLAVE == port_state(c->port[i]))
			return 0;
	}
	return 1;
}

static enum servo_state clock_no_adjust(struct clock *c)
{
	double fui;
	double ratio;
	tmv_t origin2;
	struct freq_estimator *f = &c->fest;
	enum servo_state state = SERVO_UNLOCKED;
	/*
	 * We have clock.t1 as the origin time stamp, and clock.t2 as
	 * the ingress. According to the master's clock, the time at
	 * which the sync arrived is:
	 *
	 *    origin = origin_ts + path_delay + correction
	 *
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
	if (!f->ingress1) {
		f->ingress1 = c->t2;
		f->origin1 = tmv_add(c->t1, tmv_add(c->c1, c->c2));
		return state;
	}
	f->count++;
	if (f->count < f->max_count) {
		return state;
	}
	if (tmv_eq(c->t2, f->ingress1)) {
		pr_warning("bad timestamps in rate ratio calculation");
		return state;
	}
	/*
	 * origin2 = c->t1 (+c->path_delay) + c->c1 + c->c2;
	 */
	origin2 = tmv_add(c->t1, tmv_add(c->c1, c->c2));

	ratio = tmv_dbl(tmv_sub(origin2, f->origin1)) /
		tmv_dbl(tmv_sub(c->t2, f->ingress1));

	pr_info("master offset %10lld s%d ratio %.9f path delay %10lld",
		c->master_offset, state, ratio, c->path_delay);

	fui = 1.0 + (c->status.cumulativeScaledRateOffset + 0.0) / POW2_41;

	pr_debug("peer/local    %.9f", c->nrr);
	pr_debug("fup_info      %.9f", fui);
	pr_debug("product       %.9f", fui * c->nrr);
	pr_debug("sum-1         %.9f", fui + c->nrr - 1.0);
	pr_debug("master/local  %.9f", ratio);
	pr_debug("diff         %+.9f", ratio - (fui + c->nrr - 1.0));

	f->ingress1 = c->t2;
	f->origin1 = origin2;
	f->count = 0;

	return state;
}

static void clock_ppb(clockid_t clkid, double ppb)
{
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	tx.modes = ADJ_FREQUENCY;
	tx.freq = (long) (ppb * 65.536);
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to adjust the clock: %m");
}

static double clock_ppb_read(clockid_t clkid)
{
	double f = 0.0;
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to read out the clock frequency adjustment: %m");
	else
		f = tx.freq / 65.536;
	return f;
}

static void clock_step(clockid_t clkid, int64_t ns)
{
	struct timex tx;
	int sign = 1;
	if (ns < 0) {
		sign = -1;
		ns *= -1;
	}
	memset(&tx, 0, sizeof(tx));
	tx.modes = ADJ_SETOFFSET | ADJ_NANO;
	tx.time.tv_sec  = sign * (ns / NS_PER_SEC);
	tx.time.tv_usec = sign * (ns % NS_PER_SEC);
	/*
	 * The value of a timeval is the sum of its fields, but the
	 * field tv_usec must always be non-negative.
	 */
	if (tx.time.tv_usec < 0) {
		tx.time.tv_sec  -= 1;
		tx.time.tv_usec += 1000000000;
	}
	if (clock_adjtime(clkid, &tx) < 0)
		pr_err("failed to step clock: %m");
}

static void clock_update_grandmaster(struct clock *c)
{
	memset(&c->cur, 0, sizeof(c->cur));
	memset(c->ptl, 0, sizeof(c->ptl));
	c->dad.parentPortIdentity.clockIdentity = c->dds.clockIdentity;
	c->dad.parentPortIdentity.portNumber    = 0;
	c->dad.grandmasterIdentity              = c->dds.clockIdentity;
	c->dad.grandmasterClockQuality          = c->dds.clockQuality;
	c->dad.grandmasterPriority1             = c->dds.priority1;
	c->dad.grandmasterPriority2             = c->dds.priority2;
	c->dad.path_length                      = 0;
	c->tds.currentUtcOffset                 = CURRENT_UTC_OFFSET;
	c->tds.currentUtcOffsetValid            = FALSE;
	c->tds.leap61                           = FALSE;
	c->tds.leap59                           = FALSE;
	c->tds.timeTraceable                    = FALSE;
	c->tds.frequencyTraceable               = FALSE;
	c->tds.ptpTimescale                     = c->utc_timescale ? FALSE : TRUE;
	c->tds.timeSource                       = INTERNAL_OSCILLATOR;
}

static void clock_update_slave(struct clock *c)
{
	struct ptp_message *msg        = TAILQ_FIRST(&c->best->messages);
	c->cur.stepsRemoved            = 1 + c->best->dataset.stepsRemoved;
	c->dad.parentPortIdentity      = c->best->dataset.sender;
	c->dad.grandmasterIdentity     = msg->announce.grandmasterIdentity;
	c->dad.grandmasterClockQuality = msg->announce.grandmasterClockQuality;
	c->dad.grandmasterPriority1    = msg->announce.grandmasterPriority1;
	c->dad.grandmasterPriority2    = msg->announce.grandmasterPriority2;
	c->tds.currentUtcOffset        = msg->announce.currentUtcOffset;
	c->tds.currentUtcOffsetValid   = field_is_set(msg, 1, UTC_OFF_VALID);
	c->tds.leap61                  = field_is_set(msg, 1, LEAP_61);
	c->tds.leap59                  = field_is_set(msg, 1, LEAP_59);
	c->tds.timeTraceable           = field_is_set(msg, 1, TIME_TRACEABLE);
	c->tds.frequencyTraceable      = field_is_set(msg, 1, FREQ_TRACEABLE);
	c->tds.ptpTimescale            = field_is_set(msg, 1, PTP_TIMESCALE);
	c->tds.timeSource              = msg->announce.timeSource;
	if (!c->tds.ptpTimescale) {
		pr_warning("foreign master not using PTP timescale");
	}
	if (c->tds.currentUtcOffset < CURRENT_UTC_OFFSET) {
		pr_warning("running in a temporal vortex");
	}
}

static void clock_utc_correct(struct clock *c)
{
	struct timespec offset;
	if (!c->utc_timescale)
		return;
	if (!c->tds.ptpTimescale)
		return;
	if (c->tds.currentUtcOffsetValid && c->tds.timeTraceable) {
		offset.tv_sec = c->tds.currentUtcOffset;
	} else if (c->tds.currentUtcOffset > CURRENT_UTC_OFFSET) {
		offset.tv_sec = c->tds.currentUtcOffset;
	} else {
		offset.tv_sec = CURRENT_UTC_OFFSET;
	}
	offset.tv_nsec = 0;
	/* Local clock is UTC, but master is TAI. */
	c->master_offset = tmv_add(c->master_offset, timespec_to_tmv(offset));
}

static int forwarding(struct clock *c, struct port *p)
{
	enum port_state ps = port_state(p);
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
	if (p == c->port[c->nports]) { /*uds*/
		return 1;
	}
	return 0;
}

/* public methods */

UInteger8 clock_class(struct clock *c)
{
	return c->dds.clockQuality.clockClass;
}

struct clock *clock_create(int phc_index, struct interface *iface, int count,
			   enum timestamp_type timestamping, struct defaultDS *ds,
			   enum servo_type servo)
{
	int i, fadj = 0, max_adj = 0.0, sw_ts = timestamping == TS_SOFTWARE ? 1 : 0;
	struct clock *c = &the_clock;
	char phc[32];
	struct interface udsif;

	memset(&udsif, 0, sizeof(udsif));
	snprintf(udsif.name, sizeof(udsif.name), UDS_PATH);
	udsif.transport = TRANS_UDS;

	srandom(time(NULL));

	if (c->nports)
		clock_destroy(c);

	if (c->dds.free_running) {
		c->clkid = CLOCK_INVALID;
	} else if (phc_index >= 0) {
		snprintf(phc, 31, "/dev/ptp%d", phc_index);
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
	} else {
		c->clkid = CLOCK_REALTIME;
		c->utc_timescale = 1;
		max_adj = 512000;
	}

	if (c->clkid != CLOCK_INVALID) {
		fadj = (int) clock_ppb_read(c->clkid);
	}
	c->servo = servo_create(servo, -fadj, max_adj, sw_ts);
	if (!c->servo) {
		pr_err("Failed to create clock servo");
		return NULL;
	}
	c->avg_delay = mave_create(MAVE_LENGTH);
	if (!c->avg_delay) {
		pr_err("Failed to create moving average");
		return NULL;
	}

	c->dds = *ds;

	/* Initialize the parentDS. */
	clock_update_grandmaster(c);
	c->dad.parentStats                           = 0;
	c->dad.observedParentOffsetScaledLogVariance = 0xffff;
	c->dad.observedParentClockPhaseChangeRate    = 0x7fffffff;
	c->dad.ptl = c->ptl;

	for (i = 0; i < ARRAY_SIZE(c->pollfd); i++) {
		c->pollfd[i].fd = -1;
		c->pollfd[i].events = 0;
	}

	c->fault_timeout = FAULT_RESET_SECONDS;
	c->fest.max_count = 2;

	for (i = 0; i < count; i++) {
		c->port[i] = port_open(phc_index, timestamping, 1+i, &iface[i], c);
		if (!c->port[i]) {
			pr_err("failed to open port %s", iface[i].name);
			return NULL;
		}
		c->fault_fd[i] = timerfd_create(CLOCK_MONOTONIC, 0);
		if (c->fault_fd[i] < 0) {
			pr_err("timerfd_create failed: %m");
			return NULL;
		}
		c->pollfd[N_CLOCK_PFD * i + N_POLLFD].fd = c->fault_fd[i];
		c->pollfd[N_CLOCK_PFD * i + N_POLLFD].events = POLLIN|POLLPRI;
	}

	/*
	 * One extra port is for the UDS interface.
	 */
	c->port[i] = port_open(phc_index, timestamping, 0, &udsif, c);
	if (!c->port[i]) {
		pr_err("failed to open the UDS port");
		return NULL;
	}

	c->dds.numberPorts = c->nports = count;

	for (i = 0; i < c->nports; i++)
		port_dispatch(c->port[i], EV_INITIALIZE, 0);

	port_dispatch(c->port[i], EV_INITIALIZE, 0); /*uds*/

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

void clock_follow_up_info(struct clock *c, struct follow_up_info_tlv *f)
{
	c->status.cumulativeScaledRateOffset = f->cumulativeScaledRateOffset;
	c->status.scaledLastGmPhaseChange = f->scaledLastGmPhaseChange;
	c->status.gmTimeBaseIndicator = f->gmTimeBaseIndicator;
	memcpy(&c->status.lastGmPhaseChange, &f->lastGmPhaseChange,
	       sizeof(c->status.lastGmPhaseChange));
}

struct ClockIdentity clock_identity(struct clock *c)
{
	return c->dds.clockIdentity;
}

void clock_install_fda(struct clock *c, struct port *p, struct fdarray fda)
{
	int i, j, k;
	for (i = 0; i < c->nports + 1; i++) {
		if (p == c->port[i])
			break;
	}
	for (j = 0; j < N_POLLFD; j++) {
		k = N_CLOCK_PFD * i + j;
		c->pollfd[k].fd = fda.fd[j];
		c->pollfd[k].events = POLLIN|POLLPRI;
	}
}

void clock_manage(struct clock *c, struct port *p, struct ptp_message *msg)
{
	int i, pdulen;
	struct port *fwd;
	struct management_tlv *mgt;
	struct PortIdentity pid;
	struct ClockIdentity *tcid, wildcard = {
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	};

	/* Forward this message out all eligible ports. */
	if (forwarding(c, p) && msg->management.boundaryHops) {
		pdulen = msg->header.messageLength;
		msg->management.boundaryHops--;
		msg_pre_send(msg);
		for (i = 0; i < c->nports + 1; i++) {
			fwd = c->port[i];
			if (fwd != p && forwarding(c, fwd) &&
			    port_forward(fwd, msg, pdulen))
				pr_err("port %d: management forward failed", i);
		}
		msg_post_recv(msg, pdulen);
		msg->management.boundaryHops++;
	}

	/* Apply this message to the local clock and ports. */
	tcid = &msg->management.targetPortIdentity.clockIdentity;
	if (!cid_eq(tcid, &wildcard) && !cid_eq(tcid, &c->dds.clockIdentity)) {
		return;
	}
	if (msg->tlv_count != 1) {
		return;
	}
	mgt = (struct management_tlv *) msg->management.suffix;

	if (clock_management_response(c, p, mgt->id, msg))
		return;

	switch (mgt->id) {
	case USER_DESCRIPTION:
	case SAVE_IN_NON_VOLATILE_STORAGE:
	case RESET_NON_VOLATILE_STORAGE:
	case INITIALIZE:
	case FAULT_LOG:
	case FAULT_LOG_RESET:
	case DEFAULT_DATA_SET:
	case PARENT_DATA_SET:
	case TIME_PROPERTIES_DATA_SET:
	case PRIORITY1:
	case PRIORITY2:
	case DOMAIN:
	case SLAVE_ONLY:
	case TIME:
	case CLOCK_ACCURACY:
	case UTC_PROPERTIES:
	case TRACEABILITY_PROPERTIES:
	case TIMESCALE_PROPERTIES:
	case PATH_TRACE_LIST:
	case PATH_TRACE_ENABLE:
	case GRANDMASTER_CLUSTER_TABLE:
	case ACCEPTABLE_MASTER_TABLE:
	case ACCEPTABLE_MASTER_MAX_TABLE_SIZE:
	case ALTERNATE_TIME_OFFSET_ENABLE:
	case ALTERNATE_TIME_OFFSET_NAME:
	case ALTERNATE_TIME_OFFSET_MAX_KEY:
	case ALTERNATE_TIME_OFFSET_PROPERTIES:
	case TRANSPARENT_CLOCK_DEFAULT_DATA_SET:
	case PRIMARY_DOMAIN:
		pid = port_identity(p);
		if (port_managment_error(pid, p, msg, NOT_SUPPORTED))
			pr_err("failed to send management error status");
		break;
	default:
		for (i = 0; i < c->nports; i++) {
			if (port_manage(c->port[i], p, msg))
				break;
		}
		break;
	}
}

struct parentDS *clock_parent_ds(struct clock *c)
{
	return &c->dad;
}

struct PortIdentity clock_parent_identity(struct clock *c)
{
	return c->dad.parentPortIdentity;
}

int clock_poll(struct clock *c)
{
	int cnt, i, j, k, lost = 0, sde = 0;
	enum fsm_event event;

	cnt = poll(c->pollfd, ARRAY_SIZE(c->pollfd), -1);
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

	for (i = 0; i < c->nports; i++) {

		/* Let the ports handle their events. */
		for (j = 0; j < N_POLLFD; j++) {
			k = N_CLOCK_PFD * i + j;
			if (c->pollfd[k].revents & (POLLIN|POLLPRI)) {
				event = port_event(c->port[i], j);
				if (EV_STATE_DECISION_EVENT == event)
					sde = 1;
				if (EV_ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES == event)
					lost = 1;
				port_dispatch(c->port[i], event, 0);
			}
		}

		/* Check the fault timer. */
		k = N_CLOCK_PFD * i + N_POLLFD;
		if (c->pollfd[k].revents & (POLLIN|POLLPRI)) {
			clock_fault_timeout(c, i, 0);
			port_dispatch(c->port[i], EV_FAULT_CLEARED, 0);
		}

		/* Clear any fault after a little while. */
		if (PS_FAULTY == port_state(c->port[i])) {
			clock_fault_timeout(c, i, 1);
		}
	}

	/* Check the UDS port. */
	for (j = 0; j < N_POLLFD; j++) {
		k = N_CLOCK_PFD * i + j;
		if (c->pollfd[k].revents & (POLLIN|POLLPRI)) {
			event = port_event(c->port[i], j);
		}
	}

	if (lost && clock_master_lost(c))
		clock_update_grandmaster(c);
	if (sde)
		handle_state_decision_event(c);

	return 0;
}

void clock_path_delay(struct clock *c, struct timespec req, struct timestamp rx,
		      Integer64 correction)
{
	tmv_t c1, c2, c3, pd, t1, t2, t3, t4;

	if (tmv_is_zero(c->t1))
		return;

	c1 = c->c1;
	c2 = c->c2;
	c3 = correction_to_tmv(correction);
	t1 = c->t1;
	t2 = c->t2;
	t3 = timespec_to_tmv(req);
	t4 = timestamp_to_tmv(rx);

	/*
	 * c->path_delay = (t2 - t3) + (t4 - t1);
	 * c->path_delay -= c_sync + c_fup + c_delay_resp;
	 * c->path_delay /= 2.0;
	 */
	pd = tmv_add(tmv_sub(t2, t3), tmv_sub(t4, t1));
	pd = tmv_sub(pd, tmv_add(c1, tmv_add(c2, c3)));
	pd = tmv_div(pd, 2);

	if (pd < 0) {
		pr_warning("negative path delay %10lld", pd);
		pr_warning("path_delay = (t2 - t3) + (t4 - t1)");
		pr_warning("t2 - t3 = %+10lld", t2 - t3);
		pr_warning("t4 - t1 = %+10lld", t4 - t1);
		pr_warning("c1 %10lld", c1);
		pr_warning("c2 %10lld", c2);
		pr_warning("c3 %10lld", c3);
	}

	c->path_delay = mave_accumulate(c->avg_delay, pd);

	c->cur.meanPathDelay = tmv_to_TimeInterval(c->path_delay);

	pr_debug("path delay    %10lld %10lld", c->path_delay, pd);
}

void clock_peer_delay(struct clock *c, tmv_t ppd, double nrr)
{
	c->path_delay = ppd;
	c->nrr = nrr;
}

void clock_remove_fda(struct clock *c, struct port *p, struct fdarray fda)
{
	int i, j, k;
	for (i = 0; i < c->nports + 1; i++) {
		if (p == c->port[i])
			break;
	}
	for (j = 0; j < N_POLLFD; j++) {
		k = N_CLOCK_PFD * i + j;
		c->pollfd[k].fd = -1;
		c->pollfd[k].events = 0;
	}
}

int clock_slave_only(struct clock *c)
{
	return c->dds.slaveOnly;
}

UInteger16 clock_steps_removed(struct clock *c)
{
	return c->cur.stepsRemoved;
}

enum servo_state clock_synchronize(struct clock *c,
				   struct timespec ingress_ts,
				   struct timestamp origin_ts,
				   Integer64 correction1,
				   Integer64 correction2)
{
	double adj;
	tmv_t ingress, origin;
	enum servo_state state = SERVO_UNLOCKED;

	ingress = timespec_to_tmv(ingress_ts);
	origin  = timestamp_to_tmv(origin_ts);

	c->t1 = origin;
	c->t2 = ingress;

	c->c1 = correction_to_tmv(correction1);
	c->c2 = correction_to_tmv(correction2);

	/*
	 * c->master_offset = ingress - origin - c->path_delay - c->c1 - c->c2;
	 */
	c->master_offset = tmv_sub(ingress,
		tmv_add(origin, tmv_add(c->path_delay, tmv_add(c->c1, c->c2))));

	clock_utc_correct(c);

	c->cur.offsetFromMaster = tmv_to_TimeInterval(c->master_offset);

	if (!c->path_delay)
		return state;

	if (c->dds.free_running)
		return clock_no_adjust(c);

	adj = servo_sample(c->servo, c->master_offset, ingress, &state);

	pr_info("master offset %10lld s%d adj %+7.0f path delay %10lld",
		c->master_offset, state, adj, c->path_delay);

	switch (state) {
	case SERVO_UNLOCKED:
		break;
	case SERVO_JUMP:
		clock_step(c->clkid, -c->master_offset);
		c->t1 = tmv_zero();
		c->t2 = tmv_zero();
		break;
	case SERVO_LOCKED:
		clock_ppb(c->clkid, -adj);
		break;
	}
	return state;
}

void clock_sync_interval(struct clock *c, int n)
{
	int shift = c->dds.freq_est_interval - n;

	if (shift < 0)
		shift = 0;

	c->fest.max_count = (1 << shift);
}

struct timePropertiesDS *clock_time_properties(struct clock *c)
{
	return &c->tds;
}

static void handle_state_decision_event(struct clock *c)
{
	struct foreign_clock *best = NULL, *fc;
	int fresh_best = 0, i;

	for (i = 0; i < c->nports; i++) {
		fc = port_compute_best(c->port[i]);
		if (!fc)
			continue;
		if (!best || dscmp(&fc->dataset, &best->dataset) > 0)
			best = fc;
	}

	if (!best)
		return;

	pr_notice("selected best master clock %s",
		cid2str(&best->dataset.identity));

	if (!cid_eq(&best->dataset.identity, &c->best_id)) {
		clock_freq_est_reset(c);
		mave_reset(c->avg_delay);
		fresh_best = 1;
	}

	c->best = best;
	c->best_id = best->dataset.identity;

	for (i = 0; i < c->nports; i++) {
		enum port_state ps;
		enum fsm_event event;
		ps = bmc_state_decision(c, c->port[i]);
		switch (ps) {
		case PS_LISTENING:
			event = EV_NONE;
			break;
		case PS_GRAND_MASTER:
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
		port_dispatch(c->port[i], event, fresh_best);
	}
}
