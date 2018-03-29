/**
 * @file pm.c
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
#include <stdlib.h>
#include <time.h>

#include "pm.h"
#include "print.h"


#define CYCLE_24HOUR 96
#define MIN_24HOUR_INDEX 97
#define MAX_24HOUR_INDEX 98

int pm_create_clock_stats(struct clock_pm_stats *cr)
{
	cr->masterSlaveDelay = stats_create();
	cr->slaveMasterDelay = stats_create();
	cr->meanPathDelay    = stats_create();
	cr->offsetFromMaster = stats_create();
	if (!cr->masterSlaveDelay || !cr->meanPathDelay ||
	    !cr->slaveMasterDelay || !cr->offsetFromMaster) {
		return -1;
	}
	return 0;
}

int pm_create_port_stats(struct port_pm_stats *cr)
{
	cr->meanLinkDelay = stats_create();
	if (!cr->meanLinkDelay) {
		return -1;
	}
	return 0;
}

void pm_destroy_clock_stats(struct clock_pm_stats *cr)
{
	stats_destroy(cr->masterSlaveDelay);
	stats_destroy(cr->slaveMasterDelay);
	stats_destroy(cr->meanPathDelay);
	stats_destroy(cr->offsetFromMaster);
}

void pm_destroy_port_stats(struct port_pm_stats *cr)
{
	stats_destroy(cr->meanLinkDelay);
}
void pm_free_clock_recordlist(struct clock_pm_record_list *rl)
{
	struct clock_pm_stats *tmp_s;

	while ((tmp_s = TAILQ_FIRST(&rl->record15_stats)) != NULL) {
		TAILQ_REMOVE(&rl->record15_stats, tmp_s, list);
		pm_destroy_clock_stats(tmp_s);
		free(tmp_s);
	}
	while ((tmp_s = TAILQ_FIRST(&rl->record24_stats)) != NULL) {
		TAILQ_REMOVE(&rl->record24_stats, tmp_s, list);
		pm_destroy_clock_stats(tmp_s);
		free(tmp_s);
	}
}
void pm_free_port_recordlist(struct port_pm_record_list *rl)
{
	struct port_pm_stats *tmp_s;
	struct port_pm_counters *tmp_c;

	while ((tmp_s = TAILQ_FIRST(&rl->record15_stats)) != NULL) {
		TAILQ_REMOVE(&rl->record15_stats, tmp_s, list);
		pm_destroy_port_stats(tmp_s);
		free(tmp_s);
	}
	while ((tmp_s = TAILQ_FIRST(&rl->record24_stats)) != NULL) {
		TAILQ_REMOVE(&rl->record24_stats, tmp_s, list);
		pm_destroy_port_stats(tmp_s);
		free(tmp_s);
	}
	while ((tmp_c = TAILQ_FIRST(&rl->record15_cnt)) != NULL) {
		TAILQ_REMOVE(&rl->record15_cnt, tmp_c, list);
		free(tmp_c);
	}
	while ((tmp_c = TAILQ_FIRST(&rl->record24_cnt)) != NULL) {
		TAILQ_REMOVE(&rl->record24_cnt, tmp_c, list);
		free(tmp_c);
	}
}

static void reset_clock_stats(struct clock_pm_stats *cr)
{
	stats_reset(cr->masterSlaveDelay);
	stats_reset(cr->slaveMasterDelay);
	stats_reset(cr->meanPathDelay);
	stats_reset(cr->offsetFromMaster);
}

static void reset_port_stats(struct port_pm_stats *cr)
{
	stats_reset(cr->meanLinkDelay);
}

static struct clock_pm_stats * calloc_new_clock_stats_record()
{
	struct clock_pm_stats *cr = calloc(1, sizeof(*cr));

	if (!cr) {
		pr_err("low memory, failed to create new clock stats record");
		return NULL;
	}

	return cr;
}

static struct port_pm_stats * calloc_new_port_stats_record()
{
	struct port_pm_stats *cr = calloc(1, sizeof(*cr));

	if (!cr) {
		pr_err("low memory, failed to create new port stats record");
		return NULL;
	}

	return cr;
}

static struct port_pm_counters * calloc_new_counter_record()
{
	struct port_pm_counters *cr = calloc(1, sizeof(*cr));

	if (!cr) {
		pr_err("low memory, failed to create new counter record");
		return NULL;
	}

	return cr;
}

static struct clock_pm_stats * add_new_24_clock_stats_record(struct clock_pm_record_list *rl)
{
	struct clock_pm_stats *cr = calloc_new_clock_stats_record();
	if (!cr) {
		return NULL;
	}
	if (pm_create_clock_stats(cr)) {
		pm_destroy_clock_stats(cr);
		return NULL;
	}

	cr->head.index = MIN_24HOUR_INDEX;
	TAILQ_INSERT_HEAD(&rl->record24_stats, cr, list);

	return cr;
}

static struct port_pm_stats * add_new_24_port_stats_record(struct port_pm_record_list *rl)
{
	struct port_pm_stats *cr = calloc_new_port_stats_record();
	if (!cr) {
		return NULL;
	}
	if (pm_create_port_stats(cr)) {
		pm_destroy_port_stats(cr);
		return NULL;
	}

	cr->head.index = MIN_24HOUR_INDEX;
	TAILQ_INSERT_HEAD(&rl->record24_stats, cr, list);

	return cr;
}

static struct port_pm_counters * add_new_24_counter_record(struct port_pm_record_list *rl)
{
	struct port_pm_counters *cr = calloc_new_counter_record();

	if (!cr) {
		return NULL;
	}

	cr->head.index = MIN_24HOUR_INDEX;
	TAILQ_INSERT_HEAD(&rl->record24_cnt, cr, list);

	return cr;
}

static struct clock_pm_stats * get_current_24_clock_stats_record(struct clock_pm_record_list *rl)
{
	struct clock_pm_stats *cr = TAILQ_FIRST(&rl->record24_stats);

	return (cr) ? cr : add_new_24_clock_stats_record(rl);
}

static struct port_pm_stats * get_current_24_port_stats_record(struct port_pm_record_list *rl)
{
	struct port_pm_stats *cr = TAILQ_FIRST(&rl->record24_stats);

	return (cr) ? cr : add_new_24_port_stats_record(rl);
}

static struct port_pm_counters * get_current_24_counter_record(struct port_pm_record_list *rl)
{
	struct port_pm_counters *cr = TAILQ_FIRST(&rl->record24_cnt);

	return (cr) ? cr : add_new_24_counter_record(rl);
}

static void set_index_and_pmtime(struct pm_head *cr,
				 struct pm_head *cr15,
				 struct pm_head *cr24)
{
	cr15->index  = cr->index;
	cr15->PMTime = cr->PMTime;
	if (tmv_is_zero(cr24->PMTime)) {
		cr24->PMTime = cr->PMTime;
	}
}

static void extract_clock_stats(struct clock_pm_stats *cr,
				struct clock_pm_stats *cr15,
				struct clock_pm_stats *cr24)
{
	set_index_and_pmtime(&cr->head, &cr15->head, &cr24->head);
	stats_copy(cr15->masterSlaveDelay, cr->masterSlaveDelay);
	stats_combine(cr24->masterSlaveDelay, cr->masterSlaveDelay);
	stats_copy(cr15->slaveMasterDelay, cr->slaveMasterDelay);
	stats_combine(cr24->slaveMasterDelay, cr->slaveMasterDelay);
	stats_copy(cr15->meanPathDelay, cr->meanPathDelay);
	stats_combine(cr24->meanPathDelay, cr->meanPathDelay);
	stats_copy(cr15->offsetFromMaster, cr->offsetFromMaster);
	stats_combine(cr24->offsetFromMaster, cr->offsetFromMaster);
}

static void extract_port_stats(struct port_pm_stats *cr,
			       struct port_pm_stats *cr15,
			       struct port_pm_stats *cr24)
{
	set_index_and_pmtime(&cr->head, &cr15->head, &cr24->head);
	stats_copy(cr15->meanLinkDelay, cr->meanLinkDelay);
	stats_combine(cr24->meanLinkDelay, cr->meanLinkDelay);
}

static void extract_counter_data(struct port_pm_counters *cr,
				 struct port_pm_counters *cr15,
				 struct port_pm_counters *cr24)
{
	int i;

	set_index_and_pmtime(&cr->head, &cr15->head, &cr24->head);
	for (i = 0 ; i < N_MSG_COUNTERS ; i++) {
		cr15->counter[i] = cr->counter[i] - cr24->counter[i];
		cr24->counter[i] = cr->counter[i];
	}
}

int pm_update_clock_stats_recordlist(struct clock_pm_stats *cr,
				     struct clock_pm_record_list *rl)
{
	static int pm_24h_cycle = 0;
	struct clock_pm_stats *cr15, *cr24, *tmp_s;

	cr24 = get_current_24_clock_stats_record(rl);
	if (!cr24) {
		return -1;
	}
	cr15 = calloc_new_clock_stats_record();
	if (!cr15) {
		return -1;
	}
	if (pm_create_clock_stats(cr15)) {
		pm_destroy_clock_stats(cr15);
		return -1;
	}

	extract_clock_stats(cr, cr15, cr24);

	TAILQ_INSERT_HEAD(&rl->record15_stats, cr15, list);
	TAILQ_FOREACH(tmp_s, &rl->record15_stats, list) {
		if (++tmp_s->head.index > CYCLE_24HOUR) {
			TAILQ_REMOVE(&rl->record15_stats, tmp_s, list);
			pm_destroy_clock_stats(tmp_s);
			break;
		}
	}

	if (++pm_24h_cycle == CYCLE_24HOUR) {
		pm_24h_cycle = 0;
		TAILQ_FOREACH(tmp_s, &rl->record24_stats, list) {
			if (++tmp_s->head.index > MAX_24HOUR_INDEX) {
				TAILQ_REMOVE(&rl->record24_stats, tmp_s, list);
				pm_destroy_clock_stats(tmp_s);
				break;
			}
		}
		if (!add_new_24_clock_stats_record(rl)) {
			return -1;
		}
	}

	reset_clock_stats(cr);

	return 0;
}

int pm_update_port_stats_recordlist(struct port_pm_stats *cr,
				    struct port_pm_record_list *rl)
{
	static int pm_24h_cycle = 0;
	struct port_pm_stats *cr15, *cr24, *tmp_s;

	cr24 = get_current_24_port_stats_record(rl);
	if (!cr24) {
		return -1;
	}
	cr15 = calloc_new_port_stats_record();
	if (!cr15) {
		return -1;
	}
	if (pm_create_port_stats(cr15)) {
		pm_destroy_port_stats(cr15);
		return -1;
	}

	extract_port_stats(cr, cr15, cr24);

	TAILQ_INSERT_HEAD(&rl->record15_stats, cr15, list);
	TAILQ_FOREACH(tmp_s, &rl->record15_stats, list) {
		if (++tmp_s->head.index > CYCLE_24HOUR) {
			TAILQ_REMOVE(&rl->record15_stats, tmp_s, list);
			pm_destroy_port_stats(tmp_s);
			break;
		}
	}

	if (++pm_24h_cycle == CYCLE_24HOUR) {
		pm_24h_cycle = 0;
		TAILQ_FOREACH(tmp_s, &rl->record24_stats, list) {
			if (++tmp_s->head.index > MAX_24HOUR_INDEX) {
				TAILQ_REMOVE(&rl->record24_stats, tmp_s, list);
				pm_destroy_port_stats(tmp_s);
				break;
			}
		}
		if (!add_new_24_port_stats_record(rl)) {
			return -1;
		}
	}

	reset_port_stats(cr);
	return 0;
}

int pm_update_port_counters_recordlist(struct port_pm_counters *cr,
				       struct port_pm_record_list *rl)
{
	static int pm_24h_cycle = 0;
	struct port_pm_counters *cr15, *cr24, *tmp_c;

	cr24 = get_current_24_counter_record(rl);
	if (!cr24) {
		return -1;
	}

	cr15 = calloc_new_counter_record();
	if (!cr15) {
		return -1;
	}

	extract_counter_data(cr, cr15, cr24);

	TAILQ_INSERT_HEAD(&rl->record15_cnt, cr15, list);
	TAILQ_FOREACH(tmp_c, &rl->record15_cnt, list) {
		if (++tmp_c->head.index > CYCLE_24HOUR) {
			TAILQ_REMOVE(&rl->record15_cnt, tmp_c, list);
			free(tmp_c);
			break;
		}
	}

	if (++pm_24h_cycle == CYCLE_24HOUR) {
		pm_24h_cycle = 0;
		memset(cr, 0, sizeof(*cr));
		TAILQ_FOREACH(tmp_c, &rl->record24_cnt, list) {
			if (++tmp_c->head.index > MAX_24HOUR_INDEX) {
				TAILQ_REMOVE(&rl->record24_cnt, tmp_c, list);
				free(tmp_c);
				break;
			}
		}
		if (!add_new_24_counter_record(rl)) {
			return -1;
		}
	}

	return 0;
}
