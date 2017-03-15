#include "page.h"

static struct lock page_lock;

void
page_init (void)
{
  lock_init (&page_lock);
}

unsigned
page_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  return (uint32_t) (hash_entry (e, struct page_table_entry, hash_elem)->pg_addr);
}

bool
page_less_func (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux UNUSED)
{
  uint32_t a_el = (uint32_t) (hash_entry (a, struct page_table_entry, hash_elem)->pg_addr);
  uint32_t b_el = (uint32_t) (hash_entry (b, struct page_table_entry, hash_elem)->pg_addr);

  return a_el < b_el;
}

struct page_table_entry *
page_get_data (void *addr)
{
  lock_acquire (&page_lock);
  struct page_table_entry search;
  search.pg_addr = addr;

  struct hash_elem *el = hash_find (&thread_current ()->page_table, &search.hash_elem);
  lock_release (&page_lock);
  if (el == NULL)
    return NULL;

  return hash_entry (el, struct page_table_entry, hash_elem);
}

struct page_table_entry *
page_insert_data (void *addr)
{
  lock_acquire (&page_lock);
  struct page_table_entry *new_entry = (struct page_table_entry *)
                                    malloc (sizeof (struct page_table_entry));
  if (new_entry == NULL)
    PANIC ("malloc failed in page_insert_data");

  new_entry->pg_addr = addr;
  new_entry->l = NOT_LOADED;
  new_entry->mapping_index = -1;
  hash_insert (&thread_current ()->page_table, &new_entry->hash_elem);

  lock_release (&page_lock);
  return new_entry;
}

void
page_remove_data (void *addr)
{
  struct page_table_entry *h_entry = page_get_data (addr);
  ASSERT (h_entry != NULL);
  lock_acquire (&page_lock);
  struct hash_elem *el = hash_delete (&thread_current ()->page_table, &h_entry->hash_elem);
  ASSERT (el != NULL);

  struct page_table_entry *removed_entry = hash_entry (el,
                                  struct page_table_entry, hash_elem);
  free (removed_entry);

  lock_release (&page_lock);
}
