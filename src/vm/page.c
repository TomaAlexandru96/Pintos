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
  new_entry->mapping_index = -1;
  new_entry->writable = true;
  hash_insert (&thread_current ()->page_table, &new_entry->hash_elem);

  lock_release (&page_lock);
  return new_entry;
}

void page_clear_page_table (void)
{
  void *removed_mapps[hash_size (&thread_current ()->page_table)];
  struct hash_iterator it;
  int index = 0;

  for (int i = 1; i < thread_current ()->last_vm_file_map; i++)
    {
      syscall_munmap_aux (i);
    }

  hash_first (&it, &thread_current ()->page_table);
  while (hash_next (&it))
    {
      struct page_table_entry *pt_entry =
              hash_entry (hash_cur (&it), struct page_table_entry, hash_elem);
      removed_mapps[index] = pt_entry->pg_addr;
      index++;
    }

  for (int i = 0; i < index; i++)
    {
      page_remove_data (removed_mapps[i]);
    }
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

  void *kpage = pagedir_get_page (thread_current ()->pagedir, removed_entry->pg_addr);
  if (removed_entry->l == FRAME)
    {
      pagedir_clear_page (thread_current ()->pagedir, removed_entry->pg_addr);
      palloc_free_page (kpage);
    }
  free (removed_entry);

  lock_release (&page_lock);
}
