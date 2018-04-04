/**
 * @file  pqueue.c
 * @brief Implements a priority queue.
 * @note  Copyright (c) 2015 Richard Cochran <richardcochran@gmail.com>
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "pqueue.h"

#define parent(x)	(((1 + (x)) >> 1) - 1)
#define left(x)		(((1 + (x)) << 1) - 1)
#define right(x)	(((1 + (x)) << 1))

struct pqueue {
	int len;
	int max;
	int (*cmp)(void *a, void *b);
	void **data;
};

static int pq_greater(struct pqueue *q, int a, int b)
{
	return q->cmp(q->data[a], q->data[b]) > 0 ? 1 : 0;
}

static void heapify(struct pqueue *q, int index)
{
	int i_max = index;
	int left = left(index);
	int right = right(index);

	if (left < q->len) {
		if (pq_greater(q, left, i_max))
			i_max = left;
	}

	if (right < q->len && pq_greater(q, right, i_max)) {
		i_max = right;
	}

	if (i_max != index) {
		void *tmp = q->data[index];
		q->data[index] = q->data[i_max];
		q->data[i_max] = tmp;
		heapify(q, i_max);
	}
}

/* public methods */

struct pqueue *pqueue_create(int max_length,
			     int (*compare)(void *a, void *b))
{
	struct pqueue *q = calloc(1, sizeof(*q));
	if (!q) {
		return NULL;
	}
	q->len = 0;
	q->max = max_length;
	q->cmp = compare;
	q->data = calloc(max_length, sizeof(void *));
	if (!q->data) {
		free(q);
		return NULL;
	}
	return q;
}

void pqueue_destroy(struct pqueue *q)
{
	free(q->data);
	free(q);
}

void *pqueue_extract(struct pqueue *q)
{
	void *data;

	if (!q->len) {
		return NULL;
	}
	data = q->data[0];
	q->data[0] = q->data[q->len - 1];
	q->len--;
	heapify(q, 0);

	return data;
}

int pqueue_insert(struct pqueue *q, void *d)
{
	int index;

	if (q->len >= q->max) {
		void **buf = realloc(q->data, 2 * q->max * sizeof(void *));
		if (buf) {
			q->data = buf;
			q->max *= 2;
		} else {
			return -ENOMEM;
		}
	}
	index = q->len;
	q->len++;

	while (index && (q->cmp(q->data[parent(index)], d) < 0)) {
		q->data[index] = q->data[parent(index)];
		index = parent(index);
	}
	q->data[index] = d;

	return 0;
}

int pqueue_length(struct pqueue *q)
{
	return q->len;
}

void *pqueue_peek(struct pqueue *q)
{
	return q->len ? q->data[0] : (void *) 0;
}
