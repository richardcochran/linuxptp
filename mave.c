/**
 * @file mave.c
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
#include <stdlib.h>
#include <string.h>

#include "mave.h"

struct mave {
	int cnt;
	int len;
	int index;
	tmv_t sum;
	tmv_t *val;
};

struct mave *mave_create(int length)
{
	struct mave *m;
	m = calloc(1, sizeof(*m));
	if (!m) {
		return NULL;
	}
	m->val = calloc(1, length * sizeof(*m->val));
	if (!m->val) {
		free(m);
		return NULL;
	}
	m->len = length;
	return m;
}

void mave_destroy(struct mave *m)
{
	free(m->val);
	free(m);
}

tmv_t mave_accumulate(struct mave *m, tmv_t val)
{
	m->sum = tmv_sub(m->sum, m->val[m->index]);
	m->val[m->index] = val;
	m->index = (1 + m->index) % m->len;
	m->sum = tmv_add(m->sum, val);
	if (m->cnt < m->len) {
		m->cnt++;
	}
	return tmv_div(m->sum, m->cnt);
}

void mave_reset(struct mave *m)
{
	m->cnt = 0;
	m->index = 0;
	m->sum = 0;
	memset(m->val, 0, m->len * sizeof(*m->val));
}
