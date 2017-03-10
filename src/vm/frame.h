#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include "../threads/thread.h"
#include "../lib/kernel/hash.h"
#include "../threads/palloc.h"
#include "../threads/malloc.h"
#include "../threads/synch.h"
#include "page.h"

struct frame_table_entry
  {
    struct hash_elem hash_elem;
    void *pg_addr;
  };

void frame_init (void);
struct frame_table_entry *frame_get_page (bool);
void frame_remove_page (struct frame_table_entry *);

#endif /* vm/frame.h */
