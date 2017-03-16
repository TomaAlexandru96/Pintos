#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

hash_hash_func page_hash_func;
hash_less_func page_less_func;

enum location
  {
    SWAP, NOT_LOADED, FRAME, FILE_SYS
  };

struct page_table_entry
  {
    struct hash_elem hash_elem;
    void *pg_addr;
    enum location l;
    struct file *f;
    int mapping_index;
    int map_id;
    size_t load_size;
    off_t load_offs;
  };

void page_init (void);
struct page_table_entry *page_get_data (void *);
struct page_table_entry *page_insert_data (void *);
void page_remove_data (void *);
void page_clear_page_table (void);

#endif /* vm/page.h */
