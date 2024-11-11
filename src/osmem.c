// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MMAP_THRESHOLD (128 * 1024)
#define MAP_ANONYMOUS 0x20
#define META_SIZE (sizeof(struct block_meta))

struct block_meta *head;
int heap_not_empty;

void align(size_t *offset)
{
	if (*offset % 8)
		*offset = (*offset / 8 + 1) * 8;
}

struct block_meta *try_expand(struct block_meta *p, size_t size)
{
	if (p->size < size) {
		size_t offset = size - p->size;

		align(&offset);
		sbrk(offset);
		p->size = size;
		p->status = STATUS_ALLOC;

		return p;
	}

	return NULL;
}

struct block_meta *find_available(struct block_meta **last, size_t size)
{
	struct block_meta *p = head, *best = NULL;
	size_t min = 1024 * 1024;

	while (p) {
		if (p->status == STATUS_FREE && p->size >= size && p->size < min) {
			min = p->size;
			best = p;
		}

		*last = p;
		p = p->next;
	}

	if (best)
		return best;

	if (last) {
		p = *last;
		if (p->status == STATUS_FREE)
			return try_expand(p, size);
	}

	return NULL;
}

struct block_meta *request(struct block_meta *last, size_t size, size_t threshold)
{
	struct block_meta *block;

	if (size >= threshold)
		block = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	else
		block = sbrk(size + META_SIZE);

	last->next = block;
	block->prev = last;

	block->size = size;
	block->next = NULL;

	return block;
}

int split_block(struct block_meta *block, size_t size)
{
	if (block->size > size + META_SIZE) {
		struct block_meta *new = (struct block_meta *)((char *)block + size + META_SIZE);

		new->size = block->size - size - META_SIZE;
		new->status = STATUS_FREE;
		new->next = block->next;
		new->prev = block;
		if (new->next)
			new->next->prev = new;

		block->size = size;
		block->next = new;

		return 1;
	}
	return 0;
}

void coalesce(void)
{
	struct block_meta *p = head;

	while (p) {
		if (p->next && p->status == STATUS_FREE && p->next->status == STATUS_FREE) {
			p->size += META_SIZE + p->next->size;
			p->next = p->next->next;
			if (p->next)
				p->next->prev = p;
		} else {
			p = p->next;
		}
	}
}

int merge_next(struct block_meta *p)
{
	if (p->next && p->next->status == STATUS_FREE) {
		p->size += META_SIZE + p->next->size;
		p->next = p->next->next;
		if (p->next)
			p->next->prev = p;
		return 1;
	}

	return 0;
}

void init(size_t size, size_t threshold)
{
	if (size + META_SIZE >= threshold && !heap_not_empty) {
		head = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	} else {
		head = sbrk(MMAP_THRESHOLD);
		heap_not_empty = 1;
	}

	head->next = head->prev = NULL;
	head->size = size;
}

void *alloc_helper(size_t size, size_t threshold)
{
	if (size <= 0)
		return NULL;

	struct block_meta *block;

	align(&size);
	coalesce();

	if (!head) {
		init(size, threshold);
		block = head;
	} else {
		struct block_meta *last = head;

		block = find_available(&last, size);
		if (!block) {
			if (heap_not_empty) {
				block = request(last, size, threshold);
			} else {
				block = sbrk(MMAP_THRESHOLD);
				last->next = block;
				block->prev = last;
				block->size = size;
				block->next = NULL;
			}
		} else if (block->size > size) {
			split_block(block, size);
		}
	}

	if (size + META_SIZE >= threshold)
		block->status = STATUS_MAPPED;
	else
		block->status = STATUS_ALLOC;

	return (block + 1);
}

void *os_malloc(size_t size)
{
	return alloc_helper(size, MMAP_THRESHOLD);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status != STATUS_FREE) {
		if (block->status == STATUS_MAPPED) {
			if (block->prev) {
				if (block->next) {
					block->prev->next = block->next;
					block->next->prev = block->prev;
				} else {
					block->prev->next = NULL;
				}
			} else {
				if (block->next)
					block->next->prev = NULL;
				else
					head = NULL;
			}
			munmap(block, block->size + META_SIZE);
		} else {
			block->status = STATUS_FREE;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	struct block_meta *block;
	size_t page_size = (size_t)getpagesize();

	void *payload = alloc_helper(nmemb * size, page_size);

	if (payload) {
		block = (struct block_meta *)payload - 1;
		memset(payload, 0, block->size);
	} else {
		return NULL;
	}

	return payload;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size <= 0) {
		os_free(ptr);

		return NULL;
	}

	align(&size);

	struct block_meta *block = (struct block_meta *)ptr - 1, *expanded = NULL;
	void *new = NULL;

	if (block->status == STATUS_FREE) {
		return NULL;
	} else if (block->status == STATUS_MAPPED || (size > MMAP_THRESHOLD && block->size < size)) {
		new = os_malloc(size);

		if (block->size < size)
			size = block->size;

		memcpy(new, ptr, size);
		os_free(ptr);

		return new;
	}

	if (block->size >= size) {
		split_block(block, size);

		return (block + 1);
	}

	if (!block->next)
		expanded = try_expand(block, size);

	if (expanded)
		return (expanded + 1);

	while (block->next && block->next->status == STATUS_FREE) {
		merge_next(block);

		if (block->size >= size) {
			split_block(block, size);

			return (block + 1);
		}
	}

	new = os_malloc(size);

	if (block->size < size)
			size = block->size;

	memcpy(new, ptr, size);
	os_free(ptr);

	return new;
}
