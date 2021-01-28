/**
 * @file unicast_service.c
 * @brief Unicast service
 * @note Copyright (C) 2018 Richard Cochran <richardcochran@gmail.com>
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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA.
 */
#include <stdlib.h>
#include <sys/queue.h>
#include <time.h>

#include "address.h"
#include "clock.h"
#include "missing.h"
#include "port.h"
#include "port_private.h"
#include "pqueue.h"
#include "print.h"
#include "unicast_service.h"
#include "util.h"

#define QUEUE_LEN 16

struct unicast_client_address {
	LIST_ENTRY(unicast_client_address) list;
	struct PortIdentity portIdentity;
	unsigned int message_types;
	struct address addr;
	time_t grant_tmo;
};

struct unicast_service_interval {
	LIST_HEAD(uca, unicast_client_address) clients;
	LIST_ENTRY(unicast_service_interval) list;
	struct timespec incr;
	struct timespec tmo;
	int log_period;
};

struct unicast_service {
	LIST_HEAD(usi, unicast_service_interval) intervals;
	struct pqueue *queue;
};

static struct timespec log_to_timespec(int log_seconds);
static int timespec_compare(struct timespec *a, struct timespec *b);
static void timespec_normalize(struct timespec *ts);

static int attach_grant(struct ptp_message *msg,
			struct request_unicast_xmit_tlv *req,
			int duration)
{
	struct grant_unicast_xmit_tlv *g;
	struct tlv_extra *extra;

	extra = msg_tlv_append(msg, sizeof(*g));
	if (!extra) {
		return -1;
	}
	g = (struct grant_unicast_xmit_tlv *) extra->tlv;
	g->type = TLV_GRANT_UNICAST_TRANSMISSION;
	g->length = sizeof(*g) - sizeof(g->type) - sizeof(g->length);
	g->message_type = req->message_type;
	g->logInterMessagePeriod = req->logInterMessagePeriod;
	g->durationField = duration;
	g->flags = GRANT_UNICAST_RENEWAL_INVITED;

	return 0;
}

static int compare_timeout(void *ain, void *bin)
{
	struct unicast_service_interval *a, *b;

	a = (struct unicast_service_interval *) ain;
	b = (struct unicast_service_interval *) bin;

	return timespec_compare(&a->tmo, &b->tmo);
}

static void initialize_interval(struct unicast_service_interval *interval,
				int log_period)
{
	LIST_INIT(&interval->clients);
	interval->incr = log_to_timespec(log_period);
	clock_gettime(CLOCK_MONOTONIC, &interval->tmo);
	interval->tmo.tv_nsec += 10000000;
	timespec_normalize(&interval->tmo);
	interval->log_period = log_period;
}

static void interval_increment(struct unicast_service_interval *i)
{
	i->tmo.tv_sec += i->incr.tv_sec;
	i->tmo.tv_nsec += i->incr.tv_nsec;
	timespec_normalize(&i->tmo);
}

static struct timespec log_to_timespec(int log_seconds)
{
	struct timespec ts = {0, 0};
	uint64_t ns;
	int i;

	if (log_seconds < 0) {
		log_seconds *= -1;
		for (i = 1, ns = 500000000ULL; i < log_seconds; i++) {
			ns >>= 1;
		}
		ts.tv_nsec = ns;
	} else {
		ts.tv_sec = 1 << log_seconds;
	}
	return ts;
}

/*
 * Returns:
 *    1  if 'a' is before 'b'
 *   -1  if 'a' is after  'b'
 *    0  otherwise
 */
static int timespec_compare(struct timespec *a, struct timespec *b)
{
	if (a->tv_sec < b->tv_sec) {
		return 1;
	}
	if (b->tv_sec < a->tv_sec) {
		return -1;
	}
	if (a->tv_nsec < b->tv_nsec) {
		return 1;
	}
	if (b->tv_nsec < a->tv_nsec) {
		return -1;
	}
	return 0;
}

static void timespec_normalize(struct timespec *ts)
{
	while (ts->tv_nsec >= NS_PER_SEC) {
		ts->tv_nsec -= NS_PER_SEC;
		ts->tv_sec++;
	}
}

static int unicast_service_clients(struct port *p,
				   struct unicast_service_interval *interval)
{
	struct unicast_client_address *client, *next;
	struct timespec now;
	int err = 0;

	err = clock_gettime(CLOCK_MONOTONIC, &now);
	if (err) {
		pr_err("clock_gettime failed: %m");
		return err;
	}
	LIST_FOREACH_SAFE(client, &interval->clients, list, next) {
		pr_debug("%s wants 0x%x", pid2str(&client->portIdentity),
			 client->message_types);
		if (now.tv_sec > client->grant_tmo) {
			pr_debug("%s service of 0x%x expired",
				 pid2str(&client->portIdentity),
				 client->message_types);
			LIST_REMOVE(client, list);
			free(client);
			continue;
		}
		if (client->message_types & (1 << ANNOUNCE)) {
			if (port_tx_announce(p, &client->addr)) {
				err = -1;
			}
		}
		if (client->message_types & (1 << SYNC)) {
			if (port_tx_sync(p, &client->addr)) {
				err = -1;
			}
		}
	}
	return err;
}

static void unicast_service_extend(struct unicast_client_address *client,
				   struct request_unicast_xmit_tlv *req)
{
	struct timespec now;
	time_t tmo;
	int err;

	err = clock_gettime(CLOCK_MONOTONIC, &now);
	if (err) {
		pr_err("clock_gettime failed: %m");
		return;
	}
	tmo = now.tv_sec + req->durationField;
	if (tmo > client->grant_tmo) {
		client->grant_tmo = tmo;
		pr_debug("%s grant of 0x%x extended to %lld",
			 pid2str(&client->portIdentity),
			 client->message_types, (long long)tmo);
	}
}

static int unicast_service_rearm_timer(struct port *p)
{
	struct unicast_service_interval *interval;
	struct itimerspec tmo;
	int fd;

	fd = p->fda.fd[FD_UNICAST_SRV_TIMER];
	memset(&tmo, 0, sizeof(tmo));
	interval = pqueue_peek(p->unicast_service->queue);
	if (interval) {
		tmo.it_value = interval->tmo;
		pr_debug("arming timer tmo={%lld,%ld}",
			 (long long)interval->tmo.tv_sec, interval->tmo.tv_nsec);
	} else {
		pr_debug("stopping unicast service timer");
	}
	return timerfd_settime(fd, TFD_TIMER_ABSTIME, &tmo, NULL);
}

static int unicast_service_reply(struct port *p, struct ptp_message *dst,
				 struct request_unicast_xmit_tlv *req,
				 int duration)
{
	struct ptp_message *msg;
	int err;

	msg = port_signaling_uc_construct(p, &dst->address,
					  &dst->header.sourcePortIdentity);
	if (!msg) {
		return -1;
	}
	err = attach_grant(msg, req, duration);
	if (err) {
		goto out;
	}
	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: signaling message failed", p->log_name);
	}
out:
	msg_put(msg);
	return err;
}

/* public methods */

int unicast_service_add(struct port *p, struct ptp_message *m,
			struct tlv_extra *extra)
{
	struct unicast_client_address *client = NULL, *ctmp, *next;
	struct unicast_service_interval *interval = NULL, *itmp;
	struct request_unicast_xmit_tlv *req;
	unsigned int mask;
	uint8_t mtype;

	if (!p->unicast_service) {
		return SERVICE_DISABLED;
	}

	req = (struct request_unicast_xmit_tlv *) extra->tlv;
	mtype = req->message_type >> 4;
	mask = 1 << mtype;

	switch (mtype) {
	case ANNOUNCE:
	case SYNC:
		break;
	case DELAY_RESP:
	case PDELAY_RESP:
		return SERVICE_GRANTED;
	default:
		return SERVICE_DENIED;
	}

	LIST_FOREACH(itmp, &p->unicast_service->intervals, list) {
		/*
		 * Remember the interval of interest.
		 */
		if (itmp->log_period == req->logInterMessagePeriod) {
			interval = itmp;
		}
		/*
		 * Find any client records, and remove any stale contract.
		 */
		LIST_FOREACH_SAFE(ctmp, &itmp->clients, list, next) {
			if (!addreq(transport_type(p->trp),
				    &ctmp->addr, &m->address)) {
				continue;
			}
			if (interval == itmp) {
				if (ctmp->message_types & mask) {
					/* Contract is unchanged. */
					unicast_service_extend(ctmp, req);
					return SERVICE_GRANTED;
				}
				/* This is the one to use. */
				client = ctmp;
				continue;
			}
			/* Clear any stale contracts. */
			ctmp->message_types &= ~mask;
			if (!ctmp->message_types) {
				LIST_REMOVE(ctmp, list);
				free(ctmp);
			}
		}
	}

	if (client) {
		client->message_types |= mask;
		unicast_service_extend(client, req);
		return SERVICE_GRANTED;
	}

	client = calloc(1, sizeof(*client));
	if (!client) {
		return SERVICE_DENIED;
	}
	client->portIdentity = m->header.sourcePortIdentity;
	client->message_types = mask;
	client->addr = m->address;
	unicast_service_extend(client, req);

	if (!interval) {
		interval = calloc(1, sizeof(*interval));
		if (!interval) {
			free(client);
			return SERVICE_DENIED;
		}
		initialize_interval(interval, req->logInterMessagePeriod);
		LIST_INSERT_HEAD(&p->unicast_service->intervals, interval, list);
		if (pqueue_insert(p->unicast_service->queue, interval)) {
			LIST_REMOVE(interval, list);
			free(interval);
			free(client);
			return SERVICE_DENIED;
		}
		unicast_service_rearm_timer(p);
	}
	LIST_INSERT_HEAD(&interval->clients, client, list);
	return SERVICE_GRANTED;
}

void unicast_service_cleanup(struct port *p)
{
	struct unicast_service_interval *itmp, *inext;
	struct unicast_client_address *ctmp, *cnext;

	if (!p->unicast_service) {
		return;
	}
	LIST_FOREACH_SAFE(itmp, &p->unicast_service->intervals, list, inext) {
		LIST_FOREACH_SAFE(ctmp, &itmp->clients, list, cnext) {
			LIST_REMOVE(ctmp, list);
			free(ctmp);
		}
		LIST_REMOVE(itmp, list);
		free(itmp);
	}
	pqueue_destroy(p->unicast_service->queue);
	free(p->unicast_service);
}

int unicast_service_deny(struct port *p, struct ptp_message *m,
			 struct tlv_extra *extra)
{
	struct request_unicast_xmit_tlv *req =
		(struct request_unicast_xmit_tlv *) extra->tlv;

	return unicast_service_reply(p, m, req, 0);
}

int unicast_service_grant(struct port *p, struct ptp_message *m,
			  struct tlv_extra *extra)
{
	struct request_unicast_xmit_tlv *req =
		(struct request_unicast_xmit_tlv *) extra->tlv;

	return unicast_service_reply(p, m, req, req->durationField);
}

int unicast_service_initialize(struct port *p)
{
	struct config *cfg = clock_config(p->clock);

	if (!config_get_int(cfg, p->name, "unicast_listen")) {
		return 0;
	}
	if (config_set_section_int(cfg, p->name, "hybrid_e2e", 1)) {
		return -1;
	}
	p->unicast_service = calloc(1, sizeof(*p->unicast_service));
	if (!p->unicast_service) {
		return -1;
	}
	LIST_INIT(&p->unicast_service->intervals);

	p->unicast_service->queue = pqueue_create(QUEUE_LEN, compare_timeout);
	if (!p->unicast_service->queue) {
		free(p->unicast_service);
		return -1;
	}
	p->inhibit_multicast_service =
		config_get_int(cfg, p->name, "inhibit_multicast_service");

	return 0;
}

void unicast_service_remove(struct port *p, struct ptp_message *m,
			    struct tlv_extra *extra)
{
	struct unicast_client_address *ctmp, *next;
	struct cancel_unicast_xmit_tlv *cancel;
	struct unicast_service_interval *itmp;
	unsigned int mask;
	uint8_t mtype;

	if (!p->unicast_service) {
		return;
	}
	cancel = (struct cancel_unicast_xmit_tlv *) extra->tlv;
	if (cancel->message_type_flags & CANCEL_UNICAST_MAINTAIN_REQUEST) {
		return;
	}
	mtype = cancel->message_type_flags >> 4;
	mask = 1 << mtype;

	switch (mtype) {
	case ANNOUNCE:
	case SYNC:
		break;
	case DELAY_RESP:
	case PDELAY_RESP:
	default:
		return;
	}

	LIST_FOREACH(itmp, &p->unicast_service->intervals, list) {
		LIST_FOREACH_SAFE(ctmp, &itmp->clients, list, next) {
			if (!addreq(transport_type(p->trp),
				    &ctmp->addr, &m->address)) {
				continue;
			}
			if (ctmp->message_types & mask) {
				ctmp->message_types &= ~mask;
				if (!ctmp->message_types) {
					LIST_REMOVE(ctmp, list);
					free(ctmp);
				}
				return;
			}
		}
	}
}

int unicast_service_timer(struct port *p)
{
	struct unicast_service_interval *interval;
	int err = 0, master = 0;
	struct timespec now;

	if (!p->unicast_service) {
		return 0;
	}
	clock_gettime(CLOCK_MONOTONIC, &now);

	switch (p->state) {
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_PASSIVE:
	case PS_UNCALIBRATED:
	case PS_SLAVE:
		break;
	case PS_MASTER:
	case PS_GRAND_MASTER:
		master = 1;
		break;
	}

	while ((interval = pqueue_peek(p->unicast_service->queue)) != NULL) {

		pr_debug("peek i={2^%d} tmo={%lld,%ld}", interval->log_period,
			 (long long)interval->tmo.tv_sec, interval->tmo.tv_nsec);

		if (timespec_compare(&now, &interval->tmo) > 0) {
			break;
		}
		interval = pqueue_extract(p->unicast_service->queue);

		if (master && unicast_service_clients(p, interval)) {
			err = -1;
		}

		if (LIST_EMPTY(&interval->clients)) {
			pr_debug("retire interval 2^%d", interval->log_period);
			LIST_REMOVE(interval, list);
			free(interval);
			continue;
		}

		interval_increment(interval);
		pr_debug("next i={2^%d} tmo={%lld,%ld}", interval->log_period,
			 (long long)interval->tmo.tv_sec, interval->tmo.tv_nsec);
		pqueue_insert(p->unicast_service->queue, interval);
	}

	if (unicast_service_rearm_timer(p)) {
		err = -1;
	}
	return err;
}
