#include "frame.h"
#include <stdio.h>

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
frame_put_page (struct page_table_entry *pg, bool zero_initialized)
{
  lock_acquire (&ft_lock);
  void *addr = palloc_get_page (PAL_USER | zero_initialized ? PAL_ZERO : 0);

  if (addr == NULL)
    {
      lock_release (&ft_lock);
      frame_evict_page (frame_evict_algo ());
      addr = palloc_get_page (PAL_USER | zero_initialized ? PAL_ZERO : 0);
      lock_acquire (&ft_lock);
    }

  pagedir_set_page (thread_current ()->pagedir, pg->pg_addr, addr, pg->writable);
  pg->l = FRAME;

  struct frame_table_entry *h_entry = (struct frame_table_entry *)
                                    malloc(sizeof(struct frame_table_entry));
  if (h_entry == NULL)
    {
      PANIC("malloc failed at frame_get_page");
    }
  h_entry->pg_addr = addr;
  h_entry->u_page = pg;
  hash_insert (&frame_table, &h_entry->hash_elem);
  lock_release (&ft_lock);

  return h_entry;
}

/* For now the alforithm is based on random selection of frames */
void *
frame_evict_algo (void)
{
  lock_acquire (&ft_lock);
  int frame_table_size = (int) hash_size (&frame_table);
  int rand_idx = (int) (random_ulong () % frame_table_size) + 1;

  struct hash_iterator itr;
  hash_first (&itr, &frame_table);
  for (int i = 0; i < rand_idx; i++)
    {
      hash_next (&itr);
    }

  struct page_table_entry *pt_entry =
            hash_entry (hash_cur (&itr), struct page_table_entry, hash_elem);

  lock_release (&ft_lock);
  return pt_entry->pg_addr;
}

void frame_evict_page (void *addr)
{
  lock_acquire (&ft_lock);
  struct frame_table_entry h_entry;
  h_entry.pg_addr = addr;
  struct hash_elem *el = hash_delete (&frame_table, &h_entry.hash_elem);
  ASSERT (el != NULL);

  struct frame_table_entry *removed_entry = hash_entry (el,
                                  struct frame_table_entry, hash_elem);
  insert_swap_slot (addr);
  removed_entry->u_page->l = SWAP;

  palloc_free_page (addr);
  free (removed_entry);
  lock_release (&ft_lock);
}

void
frame_remove_page (void *addr)
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

void
frame_reclaim (struct page_table_entry *en)
{
  frame_put_page (en, false);
  void *cpy = reclaim_swap_slot (en->pg_addr);
  memcpy(en->pg_addr, cpy, PGSIZE);
  free (cpy);
}
