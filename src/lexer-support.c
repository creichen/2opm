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

#include <string.h>
#include <stdlib.h>
#include "lexer-support.h"
#include "chash.h"
#include "errors.h"

char
unescape_char(char c)
{
	switch (c) {
	case '\'': return '\'';
	case '\"': return '\"';
	case '\\': return '\\';
	case 'a': return '\a';
	case 'b': return '\b';
	case 'e': return '\e';
	case 'f': return '\f';
	case 'n': return '\n';
	case 'r': return '\r';
	case 't': return '\t';
	case 'v': return '\v';
	}
	return 0;
}

char*
unescape_string(char *text, void (*yyerror)(const char *msg))
{
	char * result = strdup(text + 1);
	size_t length = strlen(result);

	result[--length] = 0; // Remove trailing '"'

	// now search for escape character: '\'.  For each such character we find, we
	// move the following memory block one byte towards the beginning of the string.
	char *escaped = strchr(result, '\\');
	char *dest = escaped; // block move target
	size_t aggregate_skip = 0; //

	// If a character is escaped with '\', switch to slower translation mode:

	while (escaped) {
		char replacement = unescape_char(escaped[1]);
		if (replacement) {
			*dest++ = replacement;
			aggregate_skip += 1;
			escaped += 2;
		} else if (escaped[1] == '0' && escaped[2] == 'x') {
			char *end;
			*dest++ = strtol(escaped + 3, &end, 16);
			aggregate_skip += end - escaped - 1;
			escaped = end;
		} else {
			yyerror("Illegal escape sequence in string");
			*dest++ = ' ';
			escaped += 2;
			aggregate_skip += 1;
		}

		// Done translating the escape symbols:  now we know that we must write to `dest',
		// while moving `aggregate_skip' bytes to the left.  The number of bytes is still unclear
		// at this point: we either copy to the end of the string or to the next '\' character.

		char *end = strchr(escaped, '\\');
		if (!end) {
			// end of string?
			size_t string_length_up_to_dest = dest - result;
			size_t movelen = length - string_length_up_to_dest - aggregate_skip;
			memmove(dest, dest + aggregate_skip, movelen);
			dest[movelen] = 0;
		} else {
			size_t movelen = end - escaped;
			memmove(dest, dest + aggregate_skip, movelen);
			dest += movelen;
		}
		escaped = end;
	}
	// FIXME: optimised for strings with either no or many '\' characters.  Copying all this memory is
	// potentially inefficient.
       return result;
}

static hashtable_t *name_map = NULL;

char* mk_unique_string(char *id)
{
	if (!name_map) {
		name_map = hashtable_alloc(hashtable_string_hash, (int (*)(const void *, const void *)) strcmp, 5);
	}
	char * retval = (char *) hashtable_get(name_map, id);

	if (retval) {
		// Name is already known
		return retval;
	}
	// Otherwise: new entry
	char *unique_id = strdup(id);
	hashtable_put(name_map, unique_id, unique_id, NULL);

	return unique_id;
}

void
yyerror(const char *str)
{
	error("%s", str);
}

