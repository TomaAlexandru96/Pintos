#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <string.h>
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "lib/random.h"
#include "devices/timer.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"

struct frame_table_entry
  {
    struct hash_elem hash_elem;
    void *pg_addr;
    struct page_table_entry *u_page;
  };

void frame_init (void);
struct frame_table_entry *frame_put_page (struct page_table_entry *, bool);
struct frame_table_entry *frame_evict_algo (void);
void frame_evict_page (struct frame_table_entry *);
void frame_reclaim (struct page_table_entry *);

#endif /* vm/frame.h */
