/**
 * @file  pqueue.h
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
#ifndef HAVE_PQUEUE_H
#define HAVE_PQUEUE_H

struct pqueue;

struct pqueue *pqueue_create(int max_length,
			     int (*compare)(void *a, void *b));

void pqueue_destroy(struct pqueue *q);

void *pqueue_extract(struct pqueue *q);

int pqueue_insert(struct pqueue *q, void *d);

int pqueue_length(struct pqueue *q);

void *pqueue_peek(struct pqueue *q);

#endif
