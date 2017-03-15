#include "swap.h"

static struct lock swap_lock;
struct block *swap_block;

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

void
swap_init(void)
{
  swap_block = block_register (const char *name, BLOCK_SWAP,
                               const char *extra_info, block_sector_t sizeS,
                               const struct block_operations *, void *aux);
  lock_init (&swap_lock);
}

struct block_sector_t *
insert_swap_slot (void *pg_addr)
{
  lock_acquire (&swap_lock);
  struct swap_table_entry *new_entry = (struct swap_table_entry *) malloc
                                       (sizeof (struct swap_table_entry));


  for (int i = 0; i < SWAP_SLOT_SIZE; i++) {
    swap_block =
    addr += 512;
  }

  new_entry->addr = pg_addr;
  new_entry->sector = /* some offset*/;




  lock_release (&swap_lock);
  return swap_block;
}

struct block_sector_t *
reclaim_swap_slot (void *)
{
  lock_acquire (&swap_lock);
  lock_release (&swap_lock);
}
