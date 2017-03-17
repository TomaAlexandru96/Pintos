#include "frame.h"
#include <stdio.h>

static hash_hash_func frame_hash_func;
static hash_less_func frame_less_func;

static struct hash frame_table;
static struct lock ft_lock;
static struct lock evict_lock;

/*
  Initalizes the frame table
*/
void
frame_init (void)
{
  hash_init (&frame_table, &frame_hash_func, &frame_less_func, NULL);
  lock_init (&ft_lock);
  lock_init (&evict_lock);
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
      frame_evict_page (frame_evict_algo ());
      addr = palloc_get_page (PAL_USER | zero_initialized ? PAL_ZERO : 0);
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

/* Clock evict */
struct frame_table_entry *
frame_evict_algo (void)
{
  lock_acquire (&evict_lock);

  struct hash_iterator it;
  struct frame_table_entry *ft_entry = NULL;

  hash_first (&it, &frame_table);
  while (hash_next (&it))
    {
      ft_entry = hash_entry (hash_cur (&it), struct frame_table_entry, hash_elem);
      if (pagedir_is_accessed (ft_entry->u_page->pagedir, ft_entry->u_page->pg_addr))
        {
          break;
        }
    }

  ASSERT (ft_entry != NULL);

  lock_release (&evict_lock);
  return ft_entry;
}

void frame_evict_page (struct frame_table_entry *h_entry)
{
  lock_acquire (&evict_lock);
  struct hash_elem *el = hash_delete (&frame_table, &h_entry->hash_elem);
  ASSERT (el != NULL);

  insert_swap_slot (h_entry->u_page->pg_addr);
  h_entry->u_page->l = SWAP;
  pagedir_clear_page (h_entry->u_page->pagedir,
              h_entry->u_page->pg_addr);

  palloc_free_page (h_entry->pg_addr);
  free (h_entry);
  lock_release (&evict_lock);
}

void
frame_reclaim (struct page_table_entry *en)
{
  lock_acquire (&ft_lock);
  reclaim_swap_slot (en->pg_addr);
  frame_put_page (en, false);
  lock_acquire (&ft_lock);
}
