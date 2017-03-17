#include "swap.h"
#include <stdio.h>

#define SWAP_SIZE(swap_block) ((uint32_t) block_size ((struct block *) swap_block))
#define SLOT_COUNT (SWAP_SIZE (swap_block) / BLOCK_SECTOR_SIZE)

static struct lock swap_lock;
static struct block *swap_block;
static struct bitmap *slots_map;
static struct hash swap_table;

static int get_free_slot (void);

void
swap_init(void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  slots_map = bitmap_create (SLOT_COUNT);
  lock_init (&swap_lock);
  hash_init (&swap_table, &swap_hash_func, &swap_less_func, NULL);
}

unsigned
swap_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  return (uint32_t) (hash_entry (e, struct swap_table_entry, hash_elem)->addr);
}

bool
swap_less_func (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux UNUSED)
{
  uint32_t a_el = (uint32_t) (hash_entry (a, struct swap_table_entry,
                                          hash_elem)->addr);
  uint32_t b_el = (uint32_t) (hash_entry (b, struct swap_table_entry,
                                          hash_elem)->addr);

  return a_el < b_el;
}

bool
is_swap_full (void)
{
  return (int) bitmap_scan (slots_map, 0, SWAP_SLOT_SIZE, false) == -1;
}

static int
get_free_slot (void)
{
  int start = 0;
  if (!is_swap_full ())
    {
      start = (int) bitmap_scan (slots_map, 0, SWAP_SLOT_SIZE, false);
      printf ("start: %d\n\n\n", start);
    }
  else
    {
      PANIC ("Swap partition is full!");
    }
    return start;
}

void
insert_swap_slot (void *pg_addr)
{
  lock_acquire (&swap_lock);
  struct swap_table_entry *new_entry = (struct swap_table_entry *) malloc
                                       (sizeof (struct swap_table_entry));
  if (new_entry == NULL)
    {
      PANIC ("Malloc failed!");
    }
  int start = get_free_slot ();
  new_entry->addr = pg_addr;
  new_entry->sector = start;
  hash_insert (&swap_table, &new_entry->hash_elem);

  for (int i = 0; i < SWAP_SLOT_SIZE; i++) {
    bitmap_set (slots_map, start + i, true);
    block_write (swap_block, start + i, (const void *) pg_addr);
    pg_addr += BLOCK_SECTOR_SIZE;
  }
  lock_release (&swap_lock);
}

void *
reclaim_swap_slot (void *pg_addr)
{
  lock_acquire (&swap_lock);
  struct swap_table_entry search;
  search.addr = pg_addr;
  struct hash_elem *elem = hash_delete (&swap_table, &search.hash_elem);

  if (elem == NULL)
    {
      // ERROR: not in swap
      return NULL;
    }

  struct swap_table_entry *reclaim_elem = hash_entry (elem,
                                          struct swap_table_entry, hash_elem);

  for (int i = 0; i < SWAP_SLOT_SIZE; i++)
    {
      bitmap_set (slots_map, reclaim_elem->sector + i, false);
    }

  void *reclaim_page = malloc (PGSIZE);
  if (reclaim_page == NULL)
    {
      PANIC ("Malloc failed!");
    }

  for (int i = 0; i < SWAP_SLOT_SIZE; i++)
    {
      block_read (swap_block, (int) reclaim_elem->sector + i, reclaim_page);
      reclaim_page += BLOCK_SECTOR_SIZE;
    }

  free (reclaim_elem);
  lock_release (&swap_lock);
  return reclaim_page;
}
