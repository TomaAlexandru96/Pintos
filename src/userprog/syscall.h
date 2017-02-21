#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"

void syscall_init (void);

/* to test memory in exception.c */
void syscall_exit_t (struct intr_frame *f, int status);

#endif /* userprog/syscall.h */
