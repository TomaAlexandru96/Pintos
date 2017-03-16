#include "frame.h"

static hash_hash_func frame_hash_func;
static hash_less_func frame_less_func;

static struct hash frame_table;
static struct lock ft_lock;

/*
  Initalizes the frame table
*/
void
frame_init (void)
{
  hash_init (&frame_table, &frame_hash_func, &frame_less_func, NULL);
  lock_init (&ft_lock);
}

static unsigned
frame_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  return (uint32_t) (hash_entry (e, struct frame_table_entry, hash_elem)->pg_addr);
}

static bool
frame_less_func (const struct hash_elem *a,
                 const struct hash_elem *b,
                 void *aux UNUSED)
{
  uint32_t a_el = (uint32_t) (hash_entry (a, struct frame_table_entry, hash_elem)->pg_addr);
  uint32_t b_el = (uint32_t) (hash_entry (b, struct frame_table_entry, hash_elem)->pg_addr);

  return a_el < b_el;
}

struct frame_table_entry *
frame_put_page (bool zero_initialized)
{
  lock_acquire (&ft_lock);
  void *addr = palloc_get_page (PAL_USER | zero_initialized ? PAL_ZERO : 0);

  if (addr == NULL)
    {
      PANIC("TODO");
    }

  struct frame_table_entry *h_entry = (struct frame_table_entry *)
                                    malloc(sizeof(struct frame_table_entry));
  if (h_entry == NULL)
    {
      PANIC("malloc failed at frame_get_page");
    }
  h_entry->pg_addr = addr;
  hash_insert (&frame_table, &h_entry->hash_elem);
  lock_release (&ft_lock);

  return h_entry;
}

void
frame_evict_page (void *addr)
{
  lock_acquire (&ft_lock);
  struct frame_table_entry h_entry;
  h_entry.pg_addr = addr;
  struct hash_elem *el = hash_delete (&frame_table, &h_entry.hash_elem);

  ASSERT (el != NULL);

  struct frame_table_entry *removed_entry = hash_entry (el,
                                  struct frame_table_entry, hash_elem);
  palloc_free_page (addr);
  free (removed_entry);
  lock_release (&ft_lock);
}
