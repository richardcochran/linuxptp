/**
 * @file pmc_agent.c
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * @note Copyright (C) 2013 Miroslav Lichvar <mlichvar@redhat.com>
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
#include <net/if.h>
#include <poll.h>
#include <stdlib.h>

#include "notification.h"
#include "pmc_agent.h"
#include "print.h"
#include "util.h"

#define PMC_UPDATE_INTERVAL (60 * NS_PER_SEC)
#define PMC_SUBSCRIBE_DURATION 180	/* 3 minutes */
/* Note that PMC_SUBSCRIBE_DURATION has to be longer than
 * PMC_UPDATE_INTERVAL otherwise subscription will time out before it is
 * renewed.
 */

struct pmc_agent {
	struct pmc *pmc;
	uint64_t pmc_last_update;

	struct defaultDS dds;
	bool dds_valid;
	int leap;
	int pmc_ds_requested;
	bool stay_subscribed;
	int sync_offset;
	int utc_offset_traceable;

	/* Callback on message reception */
	pmc_node_recv_subscribed_t *recv_subscribed;
	void *recv_context;
};

static void send_subscription(struct pmc_agent *node)
{
	struct subscribe_events_np sen;

	memset(&sen, 0, sizeof(sen));
	sen.duration = PMC_SUBSCRIBE_DURATION;
	event_bitmask_set(sen.bitmask, NOTIFY_PORT_STATE, TRUE);
	pmc_send_set_action(node->pmc, MID_SUBSCRIBE_EVENTS_NP, &sen, sizeof(sen));
}

static int check_clock_identity(struct pmc_agent *node, struct ptp_message *msg)
{
	if (!node->dds_valid) {
		return 1;
	}
	return cid_eq(&node->dds.clockIdentity,
		      &msg->header.sourcePortIdentity.clockIdentity);
}

static int is_msg_mgt(struct ptp_message *msg)
{
	struct TLV *tlv;

	if (msg_type(msg) != MANAGEMENT)
		return 0;
	if (management_action(msg) != RESPONSE)
		return 0;
	if (msg_tlv_count(msg) != 1)
		return 0;
	tlv = (struct TLV *) msg->management.suffix;
	if (tlv->type == TLV_MANAGEMENT)
		return 1;
	if (tlv->type == TLV_MANAGEMENT_ERROR_STATUS)
		return -1;
	return 0;
}

static int get_mgt_err_id(struct ptp_message *msg)
{
	struct management_error_status *mgt;

	mgt = (struct management_error_status *)msg->management.suffix;
	return mgt->id;
}

#define RUN_PMC_OKAY	 1
#define RUN_PMC_TMO	 0
#define RUN_PMC_NODEV	-1
#define RUN_PMC_INTR	-2

static bool is_run_pmc_error(int code)
{
	return code != RUN_PMC_OKAY;
}

static int run_pmc_err2errno(int code)
{
	switch (code) {
	case RUN_PMC_TMO:
		return -ETIMEDOUT;
	case RUN_PMC_NODEV:
		return -ENODEV;
	case RUN_PMC_INTR:
		return -EINTR;
	case RUN_PMC_OKAY:
	default:
		return 0;
	}
}

static int run_pmc(struct pmc_agent *node, int timeout, int ds_id,
		   struct ptp_message **msg)
{
#define N_FD 1
	struct pollfd pollfd[N_FD];
	int cnt, res;

	while (1) {
		pollfd[0].fd = pmc_get_transport_fd(node->pmc);
		pollfd[0].events = POLLIN|POLLPRI;
		if (!node->pmc_ds_requested && ds_id >= 0)
			pollfd[0].events |= POLLOUT;

		cnt = poll(pollfd, N_FD, timeout);
		if (cnt < 0) {
			pr_err("poll failed");
			return RUN_PMC_INTR;
		}
		if (!cnt) {
			/* Request the data set again in the next run. */
			node->pmc_ds_requested = 0;
			return RUN_PMC_TMO;
		}

		/* Send a new request if there are no pending messages. */
		if ((pollfd[0].revents & POLLOUT) &&
		    !(pollfd[0].revents & (POLLIN|POLLPRI))) {
			switch (ds_id) {
			case MID_SUBSCRIBE_EVENTS_NP:
				send_subscription(node);
				break;
			default:
				pmc_send_get_action(node->pmc, ds_id);
				break;
			}
			node->pmc_ds_requested = 1;
		}

		if (!(pollfd[0].revents & (POLLIN|POLLPRI)))
			continue;

		*msg = pmc_recv(node->pmc);

		if (!*msg)
			continue;

		if (!check_clock_identity(node, *msg)) {
			msg_put(*msg);
			*msg = NULL;
			continue;
		}

		res = is_msg_mgt(*msg);
		if (res < 0 && get_mgt_err_id(*msg) == ds_id) {
			node->pmc_ds_requested = 0;
			return RUN_PMC_NODEV;
		}
		if (res <= 0 ||
		    node->recv_subscribed(node->recv_context, *msg, ds_id) ||
		    management_tlv_id(*msg) != ds_id) {
			msg_put(*msg);
			*msg = NULL;
			continue;
		}
		node->pmc_ds_requested = 0;
		return RUN_PMC_OKAY;
	}
}

static int renew_subscription(struct pmc_agent *node, int timeout)
{
	struct ptp_message *msg;
	int res;

	res = run_pmc(node, timeout, MID_SUBSCRIBE_EVENTS_NP, &msg);
	if (is_run_pmc_error(res)) {
		return run_pmc_err2errno(res);
	}
	msg_put(msg);
	return 0;
}

int run_pmc_wait_sync(struct pmc_agent *node, int timeout)
{
	struct ptp_message *msg;
	Enumeration8 portState;
	void *data;
	int res;

	while (1) {
		res = run_pmc(node, timeout, MID_PORT_DATA_SET, &msg);
		if (res <= 0)
			return res;

		data = management_tlv_data(msg);
		portState = ((struct portDS *)data)->portState;
		msg_put(msg);

		switch (portState) {
		case PS_MASTER:
		case PS_SLAVE:
			return 1;
		}
		/* try to get more data sets (for other ports) */
		node->pmc_ds_requested = 1;
	}
}

int init_pmc_node(struct config *cfg, struct pmc_agent *node, const char *uds,
		  pmc_node_recv_subscribed_t *recv_subscribed, void *context)
{
	node->pmc = pmc_create(cfg, TRANS_UDS, uds, 0,
			       config_get_int(cfg, NULL, "domainNumber"),
			       config_get_int(cfg, NULL, "transportSpecific") << 4, 1);
	if (!node->pmc) {
		pr_err("failed to create pmc");
		return -1;
	}
	node->recv_subscribed = recv_subscribed;
	node->recv_context = context;

	return 0;
}

struct pmc_agent *pmc_agent_create(void)
{
	struct pmc_agent *agent = calloc(1, sizeof(*agent));
	return agent;
}

void pmc_agent_destroy(struct pmc_agent *agent)
{
	if (agent->pmc) {
		pmc_destroy(agent->pmc);
	}
	free(agent);
}

void pmc_agent_disable(struct pmc_agent *agent)
{
	if (agent->pmc) {
		pmc_destroy(agent->pmc);
	}
	agent->pmc = NULL;
}

int pmc_agent_get_leap(struct pmc_agent *agent)
{
	return agent->leap;
}

int pmc_agent_get_sync_offset(struct pmc_agent *agent)
{
	return agent->sync_offset;
}

int pmc_agent_get_number_ports(struct pmc_agent *node)
{
	if (!node->dds_valid) {
		return -1;
	}
	return node->dds.numberPorts;
}

int pmc_agent_query_dds(struct pmc_agent *node, int timeout)
{
	struct ptp_message *msg;
	struct defaultDS *dds;
	int res;

	res = run_pmc(node, timeout, MID_DEFAULT_DATA_SET, &msg);
	if (is_run_pmc_error(res)) {
		return run_pmc_err2errno(res);
	}
	dds = (struct defaultDS *) management_tlv_data(msg);
	memcpy(&node->dds, dds, sizeof(node->dds));
	node->dds_valid = true;
	msg_put(msg);
	return 0;
}

int pmc_agent_query_port_properties(struct pmc_agent *node, int timeout,
				    unsigned int port, int *state,
				    int *tstamping, char *iface)
{
	struct port_properties_np *ppn;
	struct ptp_message *msg;
	int res, len;

	pmc_target_port(node->pmc, port);
	while (1) {
		res = run_pmc(node, timeout, MID_PORT_PROPERTIES_NP, &msg);
		if (is_run_pmc_error(res)) {
			goto out;
		}
		ppn = management_tlv_data(msg);
		if (ppn->portIdentity.portNumber != port) {
			msg_put(msg);
			continue;
		}
		*state = ppn->port_state;
		*tstamping = ppn->timestamping;
		len = ppn->interface.length;
		if (len > IFNAMSIZ - 1) {
			len = IFNAMSIZ - 1;
		}
		memcpy(iface, ppn->interface.text, len);
		iface[len] = '\0';

		msg_put(msg);
		res = RUN_PMC_OKAY;
		break;
	}
out:
	pmc_target_all(node->pmc);
	return run_pmc_err2errno(res);
}

int pmc_agent_query_utc_offset(struct pmc_agent *node, int timeout)
{
	struct timePropertiesDS *tds;
	struct ptp_message *msg;
	int res;

	res = run_pmc(node, timeout, MID_TIME_PROPERTIES_DATA_SET, &msg);
	if (is_run_pmc_error(res)) {
		return run_pmc_err2errno(res);
	}

	tds = (struct timePropertiesDS *) management_tlv_data(msg);
	if (tds->flags & PTP_TIMESCALE) {
		node->sync_offset = tds->currentUtcOffset;
		if (tds->flags & LEAP_61)
			node->leap = 1;
		else if (tds->flags & LEAP_59)
			node->leap = -1;
		else
			node->leap = 0;
		node->utc_offset_traceable = tds->flags & UTC_OFF_VALID &&
					     tds->flags & TIME_TRACEABLE;
	} else {
		node->sync_offset = 0;
		node->leap = 0;
		node->utc_offset_traceable = 0;
	}
	msg_put(msg);
	return 0;
}

void pmc_agent_set_sync_offset(struct pmc_agent *agent, int offset)
{
	agent->sync_offset = offset;
}

int pmc_agent_subscribe(struct pmc_agent *node, int timeout)
{
	node->stay_subscribed = true;
	return renew_subscription(node, timeout);
}

int pmc_agent_update(struct pmc_agent *node)
{
	struct ptp_message *msg;
	struct timespec tp;
	uint64_t ts;

	if (!node->pmc) {
		return 0;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &tp)) {
		pr_err("failed to read clock: %m");
		return -errno;
	}
	ts = tp.tv_sec * NS_PER_SEC + tp.tv_nsec;

	if (ts - node->pmc_last_update >= PMC_UPDATE_INTERVAL) {
		if (node->stay_subscribed) {
			renew_subscription(node, 0);
		}
		if (!pmc_agent_query_utc_offset(node, 0)) {
			node->pmc_last_update = ts;
		}
	}

	run_pmc(node, 0, -1, &msg);

	return 0;
}

bool pmc_agent_utc_offset_traceable(struct pmc_agent *agent)
{
	return agent->utc_offset_traceable;
}
