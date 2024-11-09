// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define MAP_ANONYMOUS   0x20
#define META_SIZE (sizeof(struct block_meta))

struct block_meta *head;

void align(size_t *offset)
{
	while (*offset % 8 != 0)
		(*offset)++;
}

struct block_meta *find_available(struct block_meta **last, size_t size)
{
	struct block_meta *p = head;

	while (p) {
		if (p->size >= size && p->status == STATUS_FREE)
			return p;

		*last = p;
		p = p->next;
	}

	if (last)
		p = *last;

	if (p->status == STATUS_FREE && p->size < size) {
		size_t offset = size - p->size;
		align(&offset);
		sbrk(offset);
		p->size = size;
	}

	return NULL;
}

struct block_meta *request(struct block_meta *last, size_t size)
{
	struct block_meta *block;

	if (size >= MMAP_THRESHOLD) {
		block = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		block->status = STATUS_MAPPED;
	} else {
		block = sbrk(size + META_SIZE);
		block->status = STATUS_ALLOC;
	}

	last->next = block;
	block->prev = last;

	block->size = size;
	block->next = NULL;

	return block;
}

void split_block(struct block_meta *block, size_t size)
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
	}
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

void prealloc(size_t size)
{
	head = sbrk(MMAP_THRESHOLD);
	head->size = size;
	head->status = STATUS_ALLOC;
}

void no_prealloc(size_t size)
{
	head = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	head->size = size;
	head->status = STATUS_MAPPED;
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	size_t offset = size + META_SIZE;
	struct block_meta *block;

	align(&offset);
	align(&size);
	coalesce();

	if (!head) {
		if (size != MMAP_THRESHOLD)
			prealloc(size);

		if (size == MMAP_THRESHOLD)
			no_prealloc(MMAP_THRESHOLD);

		block = head;
		head->next = head->prev = NULL;
	} else {
		struct block_meta *last = head;

		block = find_available(&last, size);
		if (!block)
			block = request(last, size);
		else if (block->size > size)
			split_block(block, size);
	}

	if (size < MMAP_THRESHOLD)
		block->status = STATUS_ALLOC;
	else
		block->status = STATUS_MAPPED;

	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status != STATUS_FREE) {
		if (block->status == STATUS_MAPPED) {
			if (block->prev && block->next) {
				block->prev->next = block->next;
				block->next->prev = block->prev;
			} else if (!block->prev && block->next) {
				block->next->prev = NULL;
			} else if (block->prev && !block->next) {
				block->prev->next = NULL;
			}
			munmap(block, block->size + META_SIZE);
		} else {
			block->status = STATUS_FREE;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;
	void *ptr = os_malloc(total_size);

	if (ptr)
		memset(ptr, 0, total_size);

	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->size >= size)
		return ptr;

	void *new_ptr = os_malloc(size);

	if (new_ptr) {
		memcpy(new_ptr, ptr, block->size);
		os_free(ptr);
	}

	return new_ptr;
}
