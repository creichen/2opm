/***************************************************************************
  Copyright (C) 2014 Christoph Reichenbach


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

#ifndef _A2OPM_ASSEMBLER_BUFFER_H
#define _A2OPM_ASSEMBLER_BUFFER_H

#include <stdbool.h>
#include <stddef.h>

#define ASSEMBLER_BIN_PAGES_START 0xb000000000 // Binary code memory start address

typedef struct {
	size_t a, b;
	unsigned char *dest;
} pseudobuffer_t;

struct buffer_internal;
typedef struct buffer_internal* buffer_t;

// Relocation label for jumps and data access.  Resolution can be deferred.
typedef struct relative_jump_label {
	void *label_position; // Memory address that should store the result, if any
	void *base_position; // Base position relative to which we are storing the jump
} label_t;

// Sets the label to a specific memory address
void
buffer_setlabel(label_t *label, void *target);

// Sets the label to the next instruction
void
buffer_setlabel2(label_t *label, buffer_t *target);

// Extract memory address that will be used for next instruction: for use with buffer_setlabel()
void *
buffer_target(buffer_t *target);

/**
 * Allocates a buffer with the requested size.
 *
 * If the total number of bytes requested via buffer_alloc()
 * exceeds expected_size, the buffer may be relocated; see buffer_alloc() for details.
 */
buffer_t
buffer_new(size_t expected_size);

/**
 * Createas a `pseudo buffer' that works like a regular buffer but doesn't allocate memory.
 * Useful for writing into random places in RAM e.g. during dynamic compilation.
 */
buffer_t
buffer_pseudobuffer(pseudobuffer_t *buf, void *dest);

void
buffer_free(buffer_t buf);

size_t
buffer_size(buffer_t buffer);

/**
 * Allocates the specified number of bytes in the buffer and returns an address for writing.
 *
 * If the total number of allocations uses more bytes than requested at the initial buffer_new(),
 * then this call may relocate the memory underlying the buffer (i.e., buffer_entrypoint() changes).
 *
 * As a result, all labels into the buffer will become invalid.
 */
unsigned char *
buffer_alloc(buffer_t *, size_t bytes);

/**
 * Obtains the code entry point for the buffer
 */
void *
buffer_entrypoint(buffer_t buf);

/**
 * Reconstructs a buffer from its entry point.
 *
 * No error checking-- if this pointer wasn't created via buffer_entrypoint(),
 * you will get memory corruption.
 */
buffer_t
buffer_from_entrypoint(void *);

/**
 * Notifies the buffer manager that writing for this buffer is complete
 */
void
buffer_terminate(buffer_t buf);

/**
 * Disassembles the buffer to stdout
 */
void
buffer_disassemble(buffer_t buf);

/**
 * Create empty jump label
 */
label_t
buffer_label_empty();

/**
 * Is this an unused/empty jump label?
 */
bool
buffer_label_is_empty(label_t *label);

// Load Address
#define emit_la(buf, reg, p) emit_li(buf, reg, (long long) p)

#endif // !defined(_A2OPM_ASSEMBLER_BUFFER_H)
