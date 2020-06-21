/***************************************************************************
  Copyright (C) 2013 Christoph Reichenbach


 This program may be modified and copied freely according to the terms of
 the GNU general public license (GPL), as long as the above copyright
 notice and the licensing information contained herein are preserved.

 Please refer to www.gnu.org for licensing details.

 This work is provided AS IS, without warranty of any kind, expressed or
 implied, including but not limited to the warranties of merchantability,
 noninfringement, and fitness for a specific purpose. The author will not
 be held liable for any damage caused by this work or derivatives of it.

 By using this source code, you agree to the licensing terms as stated
 above.


 Please contact the maintainer for bug reports or inquiries.

 Current Maintainer:

    Christoph Reichenbach (CR) <creichen@gmail.com>

***************************************************************************/

#ifndef _CHASH_H
#define _CHASH_H

#include <stdbool.h>
#include <stdio.h>

// Number of linear follow-up addresses for `open address' resolution when handling hash conflicts
#define OPEN_ADDRESS_LINEAR_LENGTH 4

struct hashtable;

// hash table type
typedef struct hashtable hashtable_t;

// type of hash functions, mapping table keys to unsigned longs
typedef unsigned long (*hash_fn_t)(const void *);

// type of comparison functions; yield 0 when equal
typedef int (*compare_fn_t)(const void *, const void *);

// type of visitor functions for hashtable_foreach
typedef void (*visit_fn_t)(void *key, void *value, void *state);

// hash function for character strings
hash_fn_t hashtable_string_hash;

// hash function for pointers
hash_fn_t hashtable_pointer_hash;
// comparison function for pointers
compare_fn_t hashtable_pointer_compare;

// hash function for long numbers
hash_fn_t hashtable_long_hash;
// comparison function for longs
compare_fn_t hashtable_long_compare;

// ================================================================================
// hash tables

/*
 * Allocates a new empty hash table
 *
 * During allocation, hashing and comparison functions must be supplied.
 *
 * @param hash_fn 	 hashing function to use 
 * @param compare_fn	 comparison function to use
 * @param size_exponent  initial size expontent (i.e., log_2 of initial table size)
 */
hashtable_t *
hashtable_alloc(hash_fn_t hash_fn, compare_fn_t compare_fn, unsigned char size_exponent);

/*
 * Deallocates a hash table.
 *
 * Keys and values may optionally be deallocated by user-supplied functions.
 *
 * @param tbl	     table to deallocate
 * @param free_key   either NULL or a function that deallocates hash keys up the 
 * @param free_value either NULL or a function that deallocates hash values up the 
 */
void
hashtable_free(hashtable_t *tbl, void (*free_key)(void *), void (*free_value)(void *));

/*
 * Accesses the table, may insert a new entry
 *
 * Checks if an element with the key `key' is present.  If so, returns a pointer
 * to the assigned value (which can be mutated).  Otherwise returns NULL.
 * NULL is not allowed as key.
 * Does NOT modify the table if `key' is already bound inside the table.
 *
 * If no element with the key `key' is present AND `value' is != NULL,
 * this call adds a mapping `key' -> `value'.
 *
 * Automatically resizes table as needed.
 *
 * @param tbl	 table
 * @param key	 key to look up
 * @param value  value to insert, or NULL to merely check presence of key
 * @return NULL if the element was inserted, otherwise a pointer to the (mutable) existing element
 */
void **
hashtable_access(hashtable_t *tbl, void *key, void *value);

void
hashtable_put(hashtable_t *tbl, void *key, void *value, void (*free_old_value)(void *));

void *
hashtable_get(hashtable_t *tbl, void *key);

/*
 * Iterates over all table entries.
 *
 * Assume that table t maps "a" to "b" and "foo" to "bar".  Now, assume that we call
 *
 *   hashtable_foreach(t, f, &data);
 *
 * Then hashtable_foreach will invoke `f' as follows:
 *
 *   f("a", "b", &data);
 *   f("foo", "bar", &data);
 *
 * @param tbl	 table
 * @param visit  function to invoke on all key/value pairs (plus state)
 * @param state  initial state (optional; you can use this to provide an environment to `visit')
 */
void
hashtable_foreach(hashtable_t *tbl, visit_fn_t visit, void *state);

/*
 * Clones a hash table
 *
 * @param tbl		table
 * @param clone_key	function for cloning keys, or NULL if keys are to be copied
 * @param clone_vlaue	function for cloning values, or NULL if values are to be copied directly
 */
hashtable_t *
hashtable_clone(hashtable_t *tbl, void *(*clone_key)(const void *), void *(*clone_value)(const void*));


// ================================================================================
// hash sets for void *  (will not store NULL)

struct hashset_ptr;
typedef struct hashset_ptr hashset_ptr_t;

hashset_ptr_t *
hashset_ptr_alloc();

void
hashset_ptr_free(hashset_ptr_t *set);

void
hashset_ptr_add(hashset_ptr_t *set, void *ptr);

void
hashset_ptr_remove(hashset_ptr_t *set, void *ptr);

bool
hashset_ptr_contains(hashset_ptr_t *set, void *ptr);

size_t
hashset_ptr_size(hashset_ptr_t *set);

void
hashset_ptr_add_all(hashset_ptr_t *set, hashset_ptr_t *to_add);

void
hashset_ptr_remove_all(hashset_ptr_t *set, hashset_ptr_t *to_remove);

void
hashset_ptr_retain_common(hashset_ptr_t *set, hashset_ptr_t *other_set);

hashset_ptr_t *
hashset_ptr_clone(hashset_ptr_t *set);

void
hashset_ptr_foreach(hashset_ptr_t *set, void (*f)(void *ptr, void *state), void *state);

/*
 * Prints all elements of the specified set
 *
 * @param set set to print
 * @param f output stream to print to
 * @param print_element print function to print single element, or NULL to print memory address
 */
void
hashset_ptr_print(FILE *f, hashset_ptr_t *set, void (*print_element)(FILE *, void *));


// ================================================================================
// hash sets for `long' values (will not store 0x8000000000000000)

struct hashset_long;
typedef struct hashset_long hashset_long_t;

hashset_long_t *
hashset_long_alloc();

void
hashset_long_free(hashset_long_t *set);

void
hashset_long_add(hashset_long_t *set, long v);

void
hashset_long_remove(hashset_long_t *set, long v);

bool
hashset_long_contains(hashset_long_t *set, long v);

size_t
hashset_long_size(hashset_long_t *set);

void
hashset_long_add_all(hashset_long_t *set, hashset_long_t *to_add);

void
hashset_long_remove_all(hashset_long_t *set, hashset_long_t *to_remove);

void
hashset_long_retain_common(hashset_long_t *set, hashset_long_t *other_set);

hashset_long_t *
hashset_long_clone(hashset_long_t *set);

void
hashset_long_foreach(hashset_long_t *set, void (*f)(long value, void *state), void *state);

void
hashset_long_print(FILE *f, hashset_long_t *set);


#endif // !defined (_CHASH_H)
