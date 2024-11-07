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

struct block_meta *find_available(struct block_meta **last, size_t size)
{
	struct block_meta *p = head;

	while (p) {
		if (p->size >= size && p->status == STATUS_FREE)
			return p;

		*last = p;
		p = p->next;
	}
	return NULL;
}

struct block_meta *request(struct block_meta *last, size_t size)
{
	struct block_meta *block;
	int offset = size + BLOCK_SIZE;

	while (offset % 8 != 0)
		offset++;

	if (size >= MMAP_THRESHOLD) {
		block = mmap(NULL, offset, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		block->status = STATUS_MAPPED;
	} else {
		if (!head)
			block = sbrk(MMAP_THRESHOLD);
		else
			block = sbrk(offset);
		block->status = STATUS_ALLOC;
	}

	if (last) {
		last->next = block;
		block->prev = last;
	} else {
		block->prev = NULL;
	}

	block->size = offset - BLOCK_SIZE;
	block->next = NULL;

	return block;
}

void split_block(struct block_meta *block, size_t size)
{
	struct block_meta *new_block = (struct block_meta *)((char *)block + size + BLOCK_SIZE);

	new_block->size = block->size - size - BLOCK_SIZE;
	new_block->status = STATUS_FREE;
	new_block->next = block->next;
	new_block->prev = block;
	if (new_block->next)
		new_block->next->prev = new_block;

	block->size = size;
	block->next = new_block;
}

void merge_adjacent(struct block_meta *block)
{
	if (block->next && block->next->status == STATUS_FREE) {
		block->size += BLOCK_SIZE + block->next->size;
		block->next = block->next->next;
		if (block->next)
			block->next->prev = block;
	}

	if (block->prev && block->prev->status == STATUS_FREE) {
		block->prev->size += BLOCK_SIZE + block->size;
		block->prev->next = block->next;
		if (block->next)
			block->next->prev = block->prev;
	}
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	struct block_meta *block;

	if (!head) {
		block = request(NULL, size);
		head = block;
	} else {
		struct block_meta *last = head;

		block = find_available(&last, size);
		if (!block)
			block = request(last, size);
		else if (block->size > size + BLOCK_SIZE)
			split_block(block, size);
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
			merge_adjacent(block);
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
