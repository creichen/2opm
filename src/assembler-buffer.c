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

#define _DEFAULT_SOURCE // To activate MAP_ANONYMOUS
#define _DARWIN_C_SOURCE // To activate MAP_ANON

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef MAP_ANONYMOUS
#  ifndef MAP_ANON
#    error "need MAP_ANONYMOUS or MAP_ANON"
#  endif
#  define MAP_ANONYMOUS MAP_ANON
#endif

#include "assembler-buffer.h"
#include "errors.h"

#define PAGE_SIZE 0x1000 /* FIXME: extract from OS */
#define INITIAL_SIZE (PAGE_SIZE * 64)
#define MIN_INCREMENT (PAGE_SIZE * 64)

#define BUF_ALIGN_SIZE = 0x10l  // Align codemem objects to 16 bytes
#define BUF_ALIGN_MASK = (~(BUF_ALIGN_SIZE - 1))

#define MAX_ASM_WIDTH 16
#define DISASSEMBLE_PRINT_MACHINE_CODE

//#define DEBUG

// codemem objects live in code segment memory

typedef struct freelist { // codemem object type
	size_t size;  // excluding buffer_internal header
	struct freelist *next;
} freelist_t;

typedef struct buffer_internal { // codemem object type
	size_t allocd; // excluding buffer_internal, or 0 if pseudo buffer
	size_t actual;
	unsigned char data[];
} buffer_internal_t;

#define IS_PSEUDOBUFFER(buf) (!(buf)->allocd)

/* Code segment layout
 *
 * The code segment is a contiguous block of read/write/exec memory starting at code_segment
 * for code_segment_size bytes.  We allocate this size in multiples of PAGE_SIZE.
 *
 * The code segment consists of tightly packed variable size 'codemem objects':
 * - freelist_t:        unclaimed free memory, chained into a linked list
 * - buffer_internal_t: claimed incremental write buffer
 *
 * These objects are always BUF_ALIGN_MASK aligned.
 */

// The entirety of our allocated executable memory
static void *code_segment = NULL;
static size_t code_segment_size = 0;
// The "free list" of executable memory: a linked list of deallocated chunks.
// In order of recentness of deallocation.  Does NOT include code_segment_free_top.
static freelist_t *code_segment_free_list = NULL;
// Special free list entry that has a higher address than all on the free list.
static freelist_t *code_segment_free_top = NULL;

#define FREELIST

// Initialise code segment if needed
static void*
buffer_init_code_segment(size_t min_size) {
	if (!code_segment) {
		size_t alloc_size = INITIAL_SIZE;
		if (alloc_size < min_size) {
			alloc_size = (min_size + MIN_INCREMENT) & (~(PAGE_SIZE-1));
		}

		// alloc executable memory
		code_segment = mmap((void *) ASSEMBLER_BIN_PAGES_START,
				    alloc_size,
				    PROT_READ | PROT_WRITE | PROT_EXEC,
				    MAP_PRIVATE | MAP_ANONYMOUS,
				    -1,
				    0);
		if (code_segment == MAP_FAILED) {
			perror("code segment mmap");
			return NULL;
		}

		if (!code_segment) {
			// Out of memory
			return NULL;
		}
#ifdef DEBUG
		fprintf(stderr, "[ABUF] L%d: Alloc %zx at [%p]\n", __LINE__, alloc_size, code_segment);
#endif
		code_segment_size = alloc_size;
		code_segment_free_list = NULL;
		code_segment_free_top = code_segment;
		code_segment_free_top->next = NULL;
		code_segment_free_top->size = alloc_size - sizeof(buffer_internal_t);
#ifdef DEBUG
		fprintf(stderr, "[ABUF] L%d: Free-top at %p: next=%p, size=%zx\n", __LINE__, code_segment_free_top, code_segment_free_top->next, code_segment_free_top->size);
#endif
	}
	return code_segment;
}

// Allocate from freelist, if possible, or return NULL
static buffer_internal_t *
code_alloc_from_freelist(freelist_t **freelist_ptr, size_t size) {
	freelist_t **free = freelist_ptr;
	while (*free) {
		if ((*free)->size >= size) { // pick the first hit that is big enough
			freelist_t *buf_freelist = *free;
			buffer_internal_t *buf = (buffer_internal_t *) *free;
			// The buffer implicitly has the same allcoated size as the freelist entry
			// unchain
			(*free) = buf_freelist->next;
			buf->actual = 0;
#ifdef DEBUG
			fprintf(stderr, "[ABUF] L%d: Freelist at %p: ", __LINE__, code_segment_free_list);
			if (code_segment_free_list) {
				fprintf(stderr, "next=%p, size=%zx", code_segment_free_list->next, code_segment_free_list->size);
			}
			fprintf(stderr, "\n");
#endif
			return buf;
		}
		free = &((*free)->next);
	}
	return NULL; // no hit
}

static void *
code_grow_segment(size_t requested_alloc_size) {
	const size_t old_size = code_segment_size;
	size_t alloc_size = (requested_alloc_size + PAGE_SIZE - 1) & (~(PAGE_SIZE-1));
	if (alloc_size < MIN_INCREMENT) {
		alloc_size = MIN_INCREMENT;
	}
	void *new_memory_location = ((char *) code_segment) + old_size;

	// The following won't work on OS X:
	//void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...);
	//code_segment = (buffer_internal_t *) mremap(code_segment, old_size, alloc_size, 0);
	// Thus we use:
	void *code_segment2 = mmap(new_memory_location,
				   alloc_size,
				   PROT_READ | PROT_WRITE | PROT_EXEC,
				   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				   -1,
				   0);
	//exit(0);
	if (code_segment2 == MAP_FAILED) {
		perror("mmap");
		fprintf(stderr, "Failed: mmap(%p, %zx, ...)\n", ((char *) code_segment) + old_size, alloc_size);
		// Out of memory
		return NULL;
	}

	// Ensure contiguous layout.
	assert(new_memory_location == code_segment2);
	code_segment_size += alloc_size;

	if (code_segment_free_top) {
		// directly grow
		code_segment_free_top->size += alloc_size;
	} else {
		// alloc fresh
		code_segment_free_top = new_memory_location;
		code_segment_free_top->next = NULL;
		code_segment_free_top->size = alloc_size - sizeof(buffer_internal_t);
	}
	return code_segment;
}

static buffer_internal_t *
code_alloc(size_t buf_size_without_header) // size does not include the header
{
	size_t buf_size_with_header = buf_size_without_header + sizeof(buffer_internal_t);
	assert(buf_size_with_header >= sizeof(freelist_t)); // should be guaranteed

	// init code segment if needed
	if (!buffer_init_code_segment(buf_size_with_header)) {
		return NULL; // abort if we couldn't even initialise
	}

	// First try allocating from freelist
	buffer_internal_t *result = code_alloc_from_freelist(&code_segment_free_list, buf_size_without_header);
	if (result != NULL) {
		return result;
	}
	// Now try allocating from top
	result = code_alloc_from_freelist(&code_segment_free_top, buf_size_without_header);
	if (result != NULL) {
		return result;
	}

	// Looks like we don't have enough space.  Let's allocate  as much as was requested,
	// rounded up to the page size, or MIN_INCREMENT, whichever is biffer.
	if (!code_grow_segment(buf_size_with_header)) {
		return NULL;
	}

#ifdef DEBUG
	fprintf(stderr, "[ABUF] L%d: Alloc added: %zx at [%p]\n", __LINE__, buf_size_without_header, code_segment);
	fprintf(stderr, "[ABUF] L%d: Freelist at %p: ", __LINE__, code_segment_free_list);
	if (code_segment_free_list) {
		fprintf(stderr, "next=%p, size=%zx", code_segment_free_list->next, code_segment_free_list->size);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "[ABUF] L%d: Free-top at %p: ", __LINE__, code_segment_free_top);
	if (code_segment_free_top) {
		fprintf(stderr, "next=%p, size=%zx", code_segment_free_top->next, code_segment_free_top->size);
	}
	fprintf(stderr, "\n");
#endif
	return code_alloc_from_freelist(&code_segment_free_top, buf_size_without_header);
}

static void
code_free(buffer_internal_t *buf)
{
	freelist_t *new_freelist = (freelist_t*) buf;
	new_freelist->next = code_segment_free_list;
	code_segment_free_list = new_freelist;
#ifdef DEBUG
	fprintf(stderr, "[ABUF] L%d: Freelist at %p: ", __LINE__, code_segment_free_list);
	if (code_segment_free_list) {
		fprintf(stderr, "next=%p, size=%zx", code_segment_free_list->next, code_segment_free_list->size);
	}
	fprintf(stderr, "\n");
#endif
	// size remains unchanged
}

static buffer_internal_t * // only used if we _actually_ ran out of space
code_realloc(buffer_internal_t *old_buf, size_t size)
{
	// FIXME: realloc breaks labels, so we should discontinue it and instead have the allocator fail

	void* old_buf_endpos = old_buf->data + old_buf->allocd;
	void* code_segment_end = ((unsigned char*) code_segment) + code_segment_size;
	if (old_buf_endpos == code_segment_free_top || old_buf_endpos == code_segment_end) {
		// We can allocate directly from the top
		if (old_buf_endpos == code_segment_end || code_segment_free_top->size < size) {
			// must grow heap first?
			code_grow_segment(size);
		}
		// steal from top
		old_buf->allocd += code_segment_free_top->size + sizeof(freelist_t);
		code_segment_free_top = NULL;
		return old_buf;
	}
	buffer_internal_t *new_buf = code_alloc(size);
#ifdef DEBUG
	fprintf(stderr, "[ABUF] L%d: Realloc'd %p ->", __LINE__, old_buf);
	fprintf(stderr, "%p (copying %zx) for %zx, now has %zx\n", new_buf, old_buf->actual, size, new_buf->allocd);
#endif
	memcpy(new_buf->data, old_buf->data, old_buf->actual);
	new_buf->actual = old_buf->actual;
	assert(new_buf->actual <= size);
	code_free(old_buf);
#ifdef DEBUG
	fprintf(stderr, "[ABUF] L%d: New buf has %zx\n", __LINE__, new_buf->allocd);
#endif
	return new_buf;
}

void
buffer_terminate(buffer_internal_t *buf)
{
	unsigned char *end = buf->data + buf->actual;
	end = (unsigned char *) ((((unsigned long) end) + sizeof(void *) - 1) & (~(sizeof(void *) - 1)));
	size_t left_over = buf->allocd - (end - buf->data);
	if (left_over < sizeof(freelist_t) + 4) {
		// can't store a freelist entry? Just account it to the current entry
		left_over = 0;
	}
	buf->allocd -= left_over;
	if (left_over != 0) {
		// then we have a new freelist entry
		freelist_t *new_freelist = ((freelist_t *)end);
		new_freelist->next = code_segment_free_list;
		new_freelist->size = left_over - sizeof(freelist_t);
		code_segment_free_list = new_freelist;
	}
#ifdef DEBUG
	fprintf(stderr, "[ABUF] L%d: Freelist at %p: ", __LINE__, code_segment_free_list);
	if (code_segment_free_list) {
		fprintf(stderr, "next=%p, size=%zx", code_segment_free_list->next, code_segment_free_list->size);
	}
	fprintf(stderr, "\n");
#endif
}

buffer_t
buffer_new(size_t expected_size)
{
	assert(expected_size > 0);
	buffer_internal_t *buf = code_alloc(expected_size);
	if (buf == NULL) {
		fail("Out of code memory!");
	}
	buf->actual = 0;
#ifdef DEBUG
	fprintf(stderr, "[ABUF] L%d: New buffer %p starts at %p, max %zx\n", __LINE__, buf, buf->data, buf->allocd);
#endif
	return buf;
}

void
buffer_free(buffer_t buf)
{
	code_free(buf);
}

size_t
buffer_size(buffer_t buffer)
{
	return buffer->actual;
}

unsigned char *
buffer_alloc(buffer_t *buf, size_t bytes)
{
	buffer_t buffer = *buf;
	if (IS_PSEUDOBUFFER(buffer)) {
		pseudobuffer_t *pb = (pseudobuffer_t *) buffer;
		unsigned char *offset = pb->dest;
		pb->dest += bytes;
		return offset;
	}

	size_t required = buffer->actual + bytes;
	if (required > buffer->allocd) {
		size_t newsize = required + bytes; // some extra space
		buffer_t newbuf = code_realloc(buffer, newsize);
		if (!newbuf) {
			fail("Out of code memory!");
		}
		*buf = buffer = newbuf;
	}
	unsigned char * retval = buffer->data + buffer->actual;
	buffer->actual += bytes;
	return retval;
}

void *
buffer_entrypoint(buffer_t buf)
{
	return &buf->data;
}

buffer_t
buffer_from_entrypoint(void *t)
{
	unsigned char *c = (unsigned char *) t;
	return (buffer_t) (c - offsetof(struct buffer_internal, data));
}

int
disassemble_one(FILE *file, unsigned char *data, int max_len);

void
buffer_disassemble(buffer_t buf)
{
	if (!buf) {
		puts("<null>");
		return;
	}
	int size = buf->actual;
	unsigned char *data = buffer_entrypoint(buf);

	while (size > 0) {
		printf("[%p]\t", data);
		int disasmd = disassemble_one(NULL, data, size);

#ifdef DISASSEMBLE_PRINT_MACHINE_CODE
		int i;
		for (i = 0; i < disasmd; i++) {
			printf(" %02x", data[i]);
		}

		for (; i < MAX_ASM_WIDTH; i++) {
			printf("   ");
		}
		printf("\t");
#endif

		disassemble_one(stdout, data, size);
		putchar('\n');
		if (!disasmd) {
			puts("Dissassembly failed:");
			while (size > 0) {
				printf(" %02x", *data);
				++data;
				--size;
			}
			puts("\nFailed to decode");
			return;
		}
		data += disasmd;
		size -= disasmd;
	}
}

void
buffer_setlabel(label_t *label, void *target)
{
	int delta = (char *)target - (char*) label->base_position;
	memcpy(label->label_position, &delta, 4);
}

void *
buffer_target(buffer_t *target)
{
	return (*target)->data + (*target)->actual;
}

void
buffer_setlabel2(label_t *label, buffer_t *buffer)
{
	buffer_setlabel(label, buffer_target(buffer));
}

buffer_t
buffer_pseudobuffer(pseudobuffer_t *buf, void *dest)
{
	buf->dest = (unsigned char *) dest;
	buf->a = 0;
	buf->b = 0;
	return (buffer_t) buf;
}

label_t
buffer_label_empty()
{
	label_t rv = { .label_position = 0, .base_position = 0 };
	return rv;
}

bool
buffer_label_is_empty(label_t *label)
{
	return !(label->label_position || label->base_position);
}
