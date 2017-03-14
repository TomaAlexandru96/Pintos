#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

hash_hash_func page_hash_func;
hash_less_func page_less_func;

enum location
  {
    SWAP, DISK, NOT_LOADED, FRAME
  };

struct page_table_entry
  {
    struct hash_elem hash_elem;
    void *pg_addr;
    enum location l;
    int mapping_index;
    int mapping_fd;
    int mapping_size;
  };

void page_init (void);
struct page_table_entry *page_get_data (void *);
struct page_table_entry *page_insert_data (void *);
void page_remove_data (void *);

#endif /* vm/page.h */
