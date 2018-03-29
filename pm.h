/**
 * @file pm.h
 * @brief Performance monitoring
 * @note Copyright (C) 2018 Anders Selhammer <anders.selhammer@est.tech>
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
#ifndef HAVE_PM_H
#define HAVE_PM_H

#include <sys/queue.h>

#include "stats.h"
#include "tmv.h"

#define PM_15M_TIMER 900

typedef tmv_t PMTimestamp;

enum {
	/* E2E and P2P */
	ANNOUNCE_TX,
	ANNOUNCE_RX,
	ANNOUNCE_FOREIGN_MASTER_RX,
	SYNC_TX,
	SYNC_RX,
	FOLLOWUP_TX,
	FOLLOWUP_RX,
	/* E2E only */
	DELAY_REQ_TX,
	DELAY_REQ_RX,
	DELAY_RESP_TX,
	DELAY_RESP_RX,
	/* P2P only */
	PDELAY_REQ_TX,
	PDELAY_REQ_RX,
	PDELAY_RESP_TX,
	PDELAY_RESP_RX,
	PDELAY_RESP_FOLLOWUP_TX,
	PDELAY_RESP_FOLLOWUP_RX,
	N_MSG_COUNTERS
};

struct pm_head {
	UInteger16          index;
	PMTimestamp         PMTime;
};

/* E2E and P2P */
struct clock_pm_stats {
	TAILQ_ENTRY(clock_pm_stats) list;
	struct pm_head      head;
	UInteger8           measurementValid;
	UInteger8           periodComplete;
	struct stats        *masterSlaveDelay;
	struct stats        *slaveMasterDelay;
	struct stats        *meanPathDelay;
	struct stats        *offsetFromMaster;
};

/* P2P only */
struct port_pm_stats {
	TAILQ_ENTRY(port_pm_stats) list;
	struct pm_head      head;
	struct stats        *meanLinkDelay;
};

/* E2E and P2P */
struct port_pm_counters {
	TAILQ_ENTRY(port_pm_counters) list;
	struct pm_head      head;
	UInteger32          counter[N_MSG_COUNTERS];
};

struct clock_pm_record_list {
	TAILQ_HEAD(clock_pm_15_stats_head, clock_pm_stats) record15_stats;
	TAILQ_HEAD(clock_pm_24_stats_head, clock_pm_stats) record24_stats;
};

struct port_pm_record_list {
	TAILQ_HEAD(port_pm_15_stats_head, port_pm_stats) record15_stats;
	TAILQ_HEAD(port_pm_24_stats_head, port_pm_stats) record24_stats;
	TAILQ_HEAD(port_pm_15_counters_head, port_pm_counters) record15_cnt;
	TAILQ_HEAD(port_pm_24_counters_head, port_pm_counters) record24_cnt;
};

/**
 * Creates stats instances for clock statistics.
 * @param cr Handle to current record.
 * @return   Zero on success, non-zero if the message is invalid.
 */
int pm_create_clock_stats(struct clock_pm_stats *cr);

/**
 * Creates stats instances for port statistics.
 * @param cr Handle to current record.
 * @return   Zero on success, non-zero if the message is invalid.
 */
int pm_create_port_stats(struct port_pm_stats *cr);

/**
 * Destroys stats instances for clock statistics.
 * @param cr Handle to current record.
 */
void pm_destroy_clock_stats(struct clock_pm_stats *cr);

/**
 * Destroys stats instances for port statistics.
 * @param cr Handle to current record.
 */
void pm_destroy_port_stats(struct port_pm_stats *cr);

/**
 * Clear the record list and frees all the memory.
 * @param rl Handle to clock recordlist.
 */
void pm_free_clock_recordlist(struct clock_pm_record_list *rl);

/**
 * Clear the record list and frees all the memory.
 * @param rl Handle to port recordlist.
 */
void pm_free_port_recordlist(struct port_pm_record_list *rl);

/**
 * Update clock stats 15 minutes and 24 hour recordlist.
 * @param cr Handle to current record to store.
 * @param rl Handle to recordlist.
 * @return   Zero on success, non-zero if the message is invalid.
 */
int pm_update_clock_stats_recordlist(struct clock_pm_stats *cr,
				     struct clock_pm_record_list *rl);

/**
 * Update port stats 15 minutes and 24 hour recordlist.
 * @param cr Handle to current record to store.
 * @param rl Handle to recordlist.
 * @return   Zero on success, non-zero if the message is invalid.
 */
int pm_update_port_stats_recordlist(struct port_pm_stats *cr,
				    struct port_pm_record_list *rl);

/**
 * Update port counters 15 minutes and 24 hour recordlist.
 * @param cr Handle to current record to store.
 * @param rl Handle to recordlist.
 * @return   Zero on success, non-zero if the message is invalid.
 */
int pm_update_port_counters_recordlist(struct port_pm_counters *cr,
				       struct port_pm_record_list *rl);

#endif
