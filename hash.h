/**
 * @file hash.h
 * @brief Implements a simple hash table.
 * @note Copyright (C) 2015 Richard Cochran <richardcochran@gmail.com>
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
#ifndef HAVE_HASH_H
#define HAVE_HASH_H

struct hash;

/**
 * Create a new hash table.
 * @return  A pointer to a new hash table on success, NULL otherwise.
 */
struct hash *hash_create(void);

/**
 * Destroy an instance of a hash table.
 * @param ht   Pointer to a hash table obtained via @ref hash_create().
 * @param func Callback function, possibly NULL, to apply to the
 *             data of each element in the table.
 */
void hash_destroy(struct hash *ht, void (*func)(void *));

/**
 * Inserts an element into a hash table.
 * @param ht   Hash table into which the element is to be stored.
 * @param key  Key that identifies the element.
 * @param data Pointer to the user data to be stored.
 * @return Zero on success and non-zero on error.  Attempting to
 *         insert a duplicate key will fail with an error.
 */
int hash_insert(struct hash *ht, const char* key, void *data);

/**
 * Looks up an element from the hash table.
 * @param ht   Hash table to consult.
 * @param key  Key identifying the element of interest.
 * @return  Pointer to the element's data, or NULL if the key is not found.
 */
void *hash_lookup(struct hash *ht, const char* key);

#endif


