#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"

/* The number of bloack sectors needed to store on page*/
#define SWAP_SLOT_SIZE 8

hash_hash_func swap_hash_func;
hash_less_func swap_less_func;
static int get_free_slot (void);
bool is_swap_full (void);

struct swap_table_entry
{
  struct hash_elem hash_elem;
  void *addr;
  block_sector_t sector;
};

void swap_init(void);
struct block_sector_t *reclaim_swap_slot (void *);
void insert_swap_slot (void *);

#endif
