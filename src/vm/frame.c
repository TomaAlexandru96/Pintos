#include "frame.h"

static hash_hash_func frame_hash_func;
static hash_less_func frame_less_func;

static struct hash frame_table;

/*
  Initalizes the frame table
*/
void
frame_init (void)
{
  hash_init (&frame_table, &frame_hash_func, &frame_less_func, NULL);
}

static unsigned 
frame_hash_func (const struct hash_elem *e, void *aux)
{
  return 0;
}

static bool
frame_less_func (const struct hash_elem *a,
                 const struct hash_elem *b,
                 void *aux)
{
  return true;
}

/*
  Returns the page and maps it to the frame slot
*/
void *
frame_get_page (void)
{
  return palloc_get_page (PAL_USER);
}

/*
  Removes the page from the frame slot
*/
void 
frame_remove_page (void *pg)
{
  palloc_free_page (pg);
}
