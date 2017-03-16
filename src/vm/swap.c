#include "swap.h"

static struct lock swap_lock;
static struct block *swap_block;
static struct bitmap *slots_map;
static struct hash swap_table;

void
swap_init(void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  swap_size = block_size (swap_block);
  slots_map = bitmap_create (swap_size / PGSIZE);
  lock_init (&swap_lock);
  hash_init (&swap_table);
}

unsigned
swap_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  return (uint32_t) (hash_entry (e, struct swap_table_entry, hash_elem)->pg_addr);
}

bool
swap_less_func (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux UNUSED)
{
  uint32_t a_el = (uint32_t) (hash_entry (a, struct swap_table_entry, hash_elem)->pg_addr);
  uint32_t b_el = (uint32_t) (hash_entry (b, struct swap_table_entry, hash_elem)->pg_addr);

  return a_el < b_el;
}

int
get_free_slot ()
{
  int slot_size = swap_size / PGSIZE;
  bool swap_full = bitmap_all (slots_map, 0, slot_size);
  int start = 0;
  if (!swap_full)
    {
      start = (int) bitmap_scan_and_flip (slots_map, start, slot_size, false);
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
  int start = get_free_slot ();
  new_entry->addr = pg_addr;
  new_entry->sector = start;
  hash_insert (&swap_table, &new_entry->hash_elem);

  for (int i = 0; i < SWAP_SLOT_SIZE; i++) {
    swap_block = block_write (block, start, (const void *) pg_addr);
    bitmap_set (slots_map, start, true);
    pg_addr += BLOCK_SECTOR_SIZE;
    start++;
  }
  lock_release (&swap_lock);
  return swap_block;
}

struct block_sector_t *
reclaim_swap_slot (void *pg_addr)
{
  lock_acquire (&swap_lock);

  struct swap_table_entry search;
  search->addr = pg_addr;

 


  struct hash_elem *elem = hash_find (&swap_table, &search->hash_elem);
  if (elem == NULL)
    {
      return NULL
    }

  for (int i = 0; i < SWAP_SLOT_SIZE; i++)
    {
      bitmap_scan_and_flip (&swap_table, 0, SWAP_SLOT_SIZE, false);
    }

  lock_release (&swap_lock);
  return NULL;
}
