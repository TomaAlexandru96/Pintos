#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "../threads/thread.h"
#include "../lib/kernel/hash.h"
#include "../threads/palloc.h"

struct frame_table_entry
  {
    struct hash_elem hash_elem;
    void *addr;
  };

void frame_init (void);
void *frame_get_page (void);
void frame_remove_page (void *);

#endif /* vm/frame.h */
