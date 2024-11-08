// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define MAP_ANONYMOUS   0x20
#define BLOCK_SIZE (sizeof(struct block_meta))

void *head;

void align(int *offset)
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

		if (!p->next && p->status == STATUS_FREE) {
			align(&size);
			sbrk(size);
			p->size += size;

			return p;
		}

		*last = p;
		p = p->next;
	}
	return NULL;
}

struct block_meta *request(struct block_meta *last, size_t size)
{
	struct block_meta *block;

	if (size >= MMAP_THRESHOLD) {
		block = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		block->status = STATUS_MAPPED;
	} else {
		if (!head)
			block = sbrk(MMAP_THRESHOLD);
		else {
			align(&size);
			block = sbrk(size);
		}
		block->status = STATUS_ALLOC;
	}

	if (last) {
		last->next = block;
		block->prev = last;
	} else {
		block->prev = NULL;
	}

	block->size = size - BLOCK_SIZE;
	block->next = NULL;

	return block;
}

void split_block(struct block_meta *block, size_t size)
{
	if (block->size > size + BLOCK_SIZE + 8) {
		struct block_meta *new = (struct block_meta *)((char *)block + size);

		new->size = block->size - size - BLOCK_SIZE;
		new->status = STATUS_FREE;
		new->next = block->next;
		new->prev = block;
		if (new->next)
			new->next->prev = new;

		block->size = size - BLOCK_SIZE;
		block->next = new;
	}
}

void coalesce(void)
{
	struct block_meta *p = head;

	while (p) {
		if (p->next && p->status == STATUS_FREE && p->next->status == STATUS_FREE) {
			p->size += BLOCK_SIZE + p->next->size;
			p->next = p->next->next;
			if (p->next)
				p->next->prev = p;
		} else {
			p = p->next;
		}
	}
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	int offset = size + BLOCK_SIZE;
	struct block_meta *block;

	align(&offset);
    coalesce();

	if (!head) {
		block = request(NULL, offset);
		head = block;
	} else {
		struct block_meta *last = head;

		block = find_available(&last, size);
		if (!block)
			block = request(last, offset);
		else if (block->size > offset)
			split_block(block, offset);
	}

	block->status = STATUS_ALLOC;
	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status != STATUS_FREE) {
		block->status = STATUS_FREE;
		if (block->size >= MMAP_THRESHOLD)
			munmap(block, block->size + BLOCK_SIZE);
		else
			coalesce();
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
