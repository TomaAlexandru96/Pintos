#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/page.h"

void syscall_init (void);
void syscall_close_aux (struct file_map *fm);
void syscall_munmap_aux (int map_id); 

#endif /* userprog/syscall.h */
