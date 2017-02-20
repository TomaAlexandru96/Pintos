#include <syscall-nr.h>
#include "userprog/syscall.h"
#include <stdio.h>
#include "threads/interrupt.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include <stdio.h>
#include <list.h>
#include <inttypes.h>

#define ARGUMENTS_IN_USER_SPACE(intr_frame, param_nr) do {is_pointer_valid (((uint32_t *) intr_frame->esp) + param_nr, intr_frame);} while (0)
#define GET_ARGUMENT(intr_frame, nr) (((uint32_t *) intr_frame->esp)[nr])

/* Process identifier */
static void syscall_handler (struct intr_frame *);

static void syscall_halt (struct intr_frame *);
static void syscall_exit (struct intr_frame *);
static void syscall_exec (struct intr_frame *);
static void syscall_wait (struct intr_frame *);
static void syscall_create (struct intr_frame *);
static void syscall_remove (struct intr_frame *);
static void syscall_open (struct intr_frame *);
static void syscall_filesize (struct intr_frame *);
static void syscall_read (struct intr_frame *);
static void syscall_write (struct intr_frame *);
static void syscall_seek (struct intr_frame *);
static void syscall_tell (struct intr_frame *);
static void syscall_close (struct intr_frame *);

static void is_pointer_valid (uint32_t *param, struct intr_frame *);
static void syscall_exit_aux (struct intr_frame *f, int status);

typedef void (*sys_func) (struct intr_frame *);

static struct lock file_lock;
static sys_func syscall_map[32];

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  syscall_map[SYS_HALT]     = syscall_halt;
  syscall_map[SYS_EXIT]     = syscall_exit;
  syscall_map[SYS_EXEC]     = syscall_exec;
  syscall_map[SYS_WAIT]     = syscall_wait;
  syscall_map[SYS_CREATE]   = syscall_create;
  syscall_map[SYS_REMOVE]   = syscall_remove;
  syscall_map[SYS_OPEN]     = syscall_open;
  syscall_map[SYS_FILESIZE] = syscall_filesize;
  syscall_map[SYS_READ]     = syscall_read;
  syscall_map[SYS_WRITE]    = syscall_write;
  syscall_map[SYS_SEEK]     = syscall_seek;
  syscall_map[SYS_TELL]     = syscall_tell;
  syscall_map[SYS_CLOSE]    = syscall_close;

  lock_init (&file_lock);
}

static void
is_pointer_valid (uint32_t *param, struct intr_frame *f UNUSED)
{
  if (!is_user_vaddr (param) || (pagedir_get_page (thread_current ()->pagedir,
                                                  param) == NULL))
    {
      syscall_exit_aux (f, -1);
    }
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  is_pointer_valid (f->esp, f);
  syscall_map[* (uint32_t *) f->esp](f);
}

/* Halt the OS. */
static void
syscall_halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

/* Terminate the user process. */
static void
syscall_exit (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int status = (int) GET_ARGUMENT (f, 1);

  syscall_exit_aux (f, status);
}

static void
syscall_exit_aux (struct intr_frame *f, int status)
{
  struct thread *t = thread_current ();

  t->return_status = status;
  f->eax = status;
  printf ("%s: exit(%d)\n", t->name, t->return_status);
  thread_exit ();
}

/* Wait for child process to finish. */
static void
syscall_wait (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int pid = (int) GET_ARGUMENT (f, 1);

  f->eax = process_wait (pid);
}

static void
syscall_tell (struct intr_frame *f UNUSED)
{

}

static void
syscall_create (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 2);
  const char *file = (const char *) GET_ARGUMENT (f, 1);
  unsigned initial_size = (unsigned) GET_ARGUMENT (f, 2);
  is_pointer_valid ((uint32_t *) file, f);

  lock_acquire (&file_lock);
  bool ret = filesys_create (file, initial_size);
  lock_release (&file_lock);
  f->eax = ret;
}

/* Writing to file. */
static void
syscall_write (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 3);
  int fd = (int) GET_ARGUMENT (f, 1);
  const void *buffer = (const char *) GET_ARGUMENT (f, 2);
  unsigned length = (unsigned) GET_ARGUMENT (f, 3);
  is_pointer_valid ((uint32_t *) buffer, f);

  lock_acquire (&file_lock);
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, length);
    }

  lock_release (&file_lock);
  f->eax = ERROR_RET_STATUS;
}

/* */
static void
syscall_filesize (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int fd = (int) GET_ARGUMENT (f, 1);
  lock_acquire (&file_lock);
  //int file_size = (int) file_length (thread_current ()->fd_map [fd]);
  lock_release (&file_lock);
  // f->eax = file_size;
}

/*  */
static void
syscall_open (struct intr_frame *frame UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (frame, 1);
  const char *file = (const char *) GET_ARGUMENT (frame, 1);

  int fd = thread_current ()->last_fd;
  lock_acquire (&file_lock);
  struct file *f = filesys_open (file);
  lock_release (&file_lock);
  if (f == NULL)
    {
      frame->eax = -1;
      return;
    }
  lock_acquire (&file_lock);
  struct file *open_file = file_open (file_get_inode (f));
  lock_release (&file_lock);
  if (open_file == NULL)
    {
      frame->eax = -1;
      return;
    }
  struct file_map fm;
  fm.fd = fd;
  fm.f = open_file;
  list_push_back (&thread_current ()->open_files, &fm.elem);
  thread_current ()->last_fd++;
  frame->eax = fd;
}

static void
syscall_exec (struct intr_frame *f)
{

}

static void
syscall_remove (struct intr_frame *f)
{

}

static void
syscall_read (struct intr_frame *f)
{

}

static void
syscall_seek (struct intr_frame *f)
{

}

static void
syscall_close (struct intr_frame *f)
{

}
