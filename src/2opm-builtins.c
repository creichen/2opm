/***************************************************************************
  Copyright (C) 2014, 2020 Christoph Reichenbach


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

#include <stdlib.h>
#include <stdio.h>
#include "debugger.h"
#include "chash.h"

// name table, for the 2opm standalone library

static hashtable_t *name_table = NULL;;

void
debug_address_record(void *addr, int kind, char *description)
{
	if (!name_table) {
		name_table = hashtable_alloc(hashtable_pointer_hash, hashtable_pointer_compare, 5);
	}
	hashtable_put(name_table, addr, description, NULL);
}

char *
debug_address_lookup(void *addr, char **prefix)
{
	if (prefix) {
		*prefix = "";
	}
	return (char *) hashtable_get(name_table, addr);
}
