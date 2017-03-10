#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include "../threads/thread.h"
#include "../lib/kernel/hash.h"
#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../threads/synch.h"

enum location 
  {
    SWAP, DISK, NOT_LOADED, FRAME
  };

struct page_table_entry
  {
    struct hash_elem hash_elem;
    void *pg_addr;
    enum location l;
  };

void page_init (void);
struct page_table_entry *page_get_data (void *);
struct page_table_entry *page_insert_data (void *);
void page_remove_data (void *);

#endif /* vm/page.h */
