// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define MAP_ANONYMOUS 0x20
#define META_SIZE (sizeof(struct block_meta))

struct block_meta *head;

/// @brief Aligns a value to 8 bytes
/// @param size
void align(size_t *size)
{
	if (*size % 8)
		*size = (*size / 8 + 1) * 8;
}

/// @brief Tries to expand the last memory block on the heap to reach 'size' bytes
/// @param p
/// @param size
/// @return The expanded block or NULL
struct block_meta *try_expand(struct block_meta *p, size_t size)
{
	if (p->size < size) {
		size_t offset = size - p->size;

		align(&offset);

		DIE(sbrk(offset) == (void *)-1, "sbrk failed");

		p->size = size;
		p->status = STATUS_ALLOC;

		return p;
	}

	return NULL;
}

/// @brief Finds the most suitable free memory block to use
/// @param last
/// @param size
/// @return Best block available
struct block_meta *find_available(struct block_meta **last, size_t size)
{
	struct block_meta *p = head, *best = NULL;

	// set min to 1gb just to be sure
	size_t min = 1024 * 1024 * 1024;

	while (p) {
		if (p->status == STATUS_FREE && p->size >= size && p->size < min) {
			// update the 'min' value whenever i find a valid smaller size
			min = p->size;
			best = p;
		}

		*last = p;
		p = p->next;
	}

	if (best)
		return best;

	p = *last;

	// try expanding the last block if free
	if (p->status == STATUS_FREE)
		return try_expand(p, size);

	return NULL;
}

/// @brief Requests memory from the heap
/// @param last
/// @param size
/// @return The newly allocated memory block
struct block_meta *request(struct block_meta *last, size_t size)
{
	struct block_meta *block;

	block = sbrk(size + META_SIZE);
	DIE(block == (void *)-1, "sbrk failed");

	last->next = block;
	block->prev = last;

	block->size = size;
	block->next = NULL;

	return block;
}

/// @brief Resizes a memory block to 'size' bytes
/// @param block
/// @param size
/// @return 1 on success, 0 if unsuccessful
int split_block(struct block_meta *block, size_t size)
{
	if (block->size > size + META_SIZE) {
		struct block_meta *new =
				(struct block_meta *)((char *)block + size + META_SIZE);

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

/// @brief Merges all the free memory blocks on the heap
void coalesce(void)
{
	struct block_meta *p = head;

	while (p) {
		if (p->next && p->status == STATUS_FREE &&
				p->next->status == STATUS_FREE) {
			p->size += META_SIZE + p->next->size;
			p->next = p->next->next;
			if (p->next)
				p->next->prev = p;
		} else {
			p = p->next;
		}
	}
}

/// @brief Merges 'block' with the next block, if free
/// @param p
/// @return 1 on success, 0 if unsuccessful
int merge_next(struct block_meta *block)
{
	if (block->next && block->next->status == STATUS_FREE) {
		block->size += META_SIZE + block->next->size;
		block->next = block->next->next;
		if (block->next)
			block->next->prev = block;
		return 1;
	}

	return 0;
}

/// @brief Allocates 'size' bytes, depending on the threshold
/// @param size
/// @param threshold
/// @return Pointer to the memory zone
void *alloc_helper(size_t size, size_t threshold)
{
	if (size <= 0)
		return NULL;

	struct block_meta *block;

	align(&size);

	// every block with a large size is mapped
	if (size + META_SIZE >= threshold) {
		block = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE,
								MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(block == NULL, "mmap failed");

		block->size = size;
		block->next = block->prev = NULL;
		block->status = STATUS_MAPPED;

		return (block + 1);
	}

	coalesce();

	if (!head) {
		// initialize the heap
		head = sbrk(MMAP_THRESHOLD);
		DIE(head == NULL, "sbrk failed");

		head->next = head->prev = NULL;
		head->size = MMAP_THRESHOLD - META_SIZE;
		block = head;
	} else {
		struct block_meta *last = head;

		// if the heap is not empty, search for a suitable block
		block = find_available(&last, size);

		// if not found, expand the heap
		if (!block)
			block = request(last, size);
	}

	// the block will be split if its size is too big
	split_block(block, size);

	block->status = STATUS_ALLOC;

	return (block + 1);
}

/// @brief Allocates 'size' bytes
/// @param size
/// @return Pointer to the memory zone
void *os_malloc(size_t size)
{
	return alloc_helper(size, MMAP_THRESHOLD);
}

/// @brief Frees the memory pointed to by 'ptr'
/// @param ptr
void os_free(void *ptr)
{
	// return on invalid block
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	// if mapped, unmap
	// otherwise, mark as free
	if (block->status != STATUS_FREE) {
		if (block->status == STATUS_MAPPED)
			munmap(block, block->size + META_SIZE);
		else
			block->status = STATUS_FREE;
	}
}

/// @brief Allocates space for an array of 'nmemb' elements of 'size'
/// bytes and initializes it with 0
/// @param nmemb
/// @param size
/// @return Pointer to the memory zone
void *os_calloc(size_t nmemb, size_t size)
{
	struct block_meta *block;
	size_t page_size = (size_t)getpagesize();

	// if the total size is smaller than 'page_size',
	// the memory will be allocated on the heap
	// if not, with mmap
	void *payload = alloc_helper(nmemb * size, page_size);

	if (payload) {
		block = (struct block_meta *)payload - 1;
		memset(payload, 0, block->size);
	} else {
		return NULL;
	}

	return payload;
}

/// @brief Reallocates the memory zone pointed to by 'ptr' to 'size' bytes
/// @param ptr
/// @param size
/// @return Pointer to the memory zone
void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size <= 0) {
		os_free(ptr);

		return NULL;
	}

	align(&size);

	struct block_meta *block = (struct block_meta *)ptr - 1;
	void *new = NULL;

	if (block->status == STATUS_FREE) {
		// invalid block
		return NULL;
	} else if (block->status == STATUS_MAPPED ||
					(size > MMAP_THRESHOLD && block->size < size)) {
		// if the block was mapped
		// create a new allocation and copy old contents
		new = os_malloc(size);

		if (block->size < size)
			size = block->size;

		memcpy(new, ptr, size);
		os_free(ptr);

		return new;
	}

	// if the block is on the heap, try to split it
	if (block->size >= size) {
		split_block(block, size);

		return (block + 1);
	}

	if (!block->next) {
		struct block_meta *expanded = NULL;

		// if the block is the last one, try to expand it
		expanded = try_expand(block, size);

		if (expanded)
			return (expanded + 1);
	}

	// try to merge with the next block until the size is right
	while (block->next && block->next->status == STATUS_FREE) {
		merge_next(block);

		if (block->size >= size) {
			split_block(block, size);

			return (block + 1);
		}
	}

	// last resort, expand the heap
	new = os_malloc(size);

	memcpy(new, ptr, block->size);
	os_free(ptr);

	return new;
}
