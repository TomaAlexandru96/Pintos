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

/* Process identifier */
typedef int pid_t;

static void syscall_handler (struct intr_frame *);

static void syscall_halt (void);
static void syscall_exit (int status);
static pid_t syscall_exec (const char *file);
static int syscall_wait (pid_t pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned size);
static int syscall_write (int fd, const void *buffer, unsigned size);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);
static void is_pointer_valid(uint32_t *param);

static struct lock file_lock;
static int syscall_args[32];

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  syscall_args[SYS_HALT] = 0;
  syscall_args[SYS_EXIT] = 1;
  syscall_args[SYS_WAIT] = 1;
  syscall_args[SYS_TELL] = 1;
  syscall_args[SYS_CREATE] = 2;
  syscall_args[SYS_WRITE] = 3;
  syscall_args[SYS_FILESIZE] = 1;

  lock_init (&file_lock);
}

static void
is_pointer_valid (uint32_t *param)
{
  if (!is_user_vaddr (param) || (pagedir_get_page (thread_current ()->pagedir,
                                                  param) == NULL))
    {
      syscall_exit (-1);
    }
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t *base = f->esp;
  uint32_t ret = f->eax;
  is_pointer_valid (base);
  is_pointer_valid (base + syscall_args[*base]);
  switch (*base)
    {
      case SYS_HALT: syscall_halt (); break;
      case SYS_EXIT: syscall_exit ((int) base[1]); break;
      case SYS_WAIT: ret = (uint32_t) syscall_wait ((pid_t) base[1]); break;
      case SYS_WRITE: ret = (uint32_t) syscall_write ((int) base[1],
                                      (const void *) base[2],
                                      (unsigned) base[3]); break;
      case SYS_FILESIZE : ret = (uint32_t) syscall_filesize((int) base[1]);
                                break;
      case SYS_CREATE: ret = (uint32_t) syscall_create ((const char *) base[1],
                                          (unsigned) base[2]); break;
      case SYS_TELL: ret = (uint32_t) syscall_tell ((int) base[1]);
    }

    f->eax = ret;
}

/* Halt the OS. */
static void
syscall_halt (void)
{
  shutdown_power_off ();
}

/* Terminate the user process. */
static void
syscall_exit (int status)
{
  struct thread *t;

  t = thread_current ();
  // Implement close files

  t->return_status = status;

  thread_exit ();
}

/* Wait for child process to finish. */
static int
syscall_wait (pid_t pid)
{
  return process_wait (pid);
}

static unsigned
syscall_tell (int fd)
{
  return 0;  
}

static bool
syscall_create (const char *file, unsigned initial_size)
{
  is_pointer_valid ((uint32_t *) file);

  lock_acquire (&file_lock);
  bool ret = filesys_create (file, initial_size);
  lock_release (&file_lock);
  return ret;
}

/* Writing to file. */
static int
syscall_write (int fd, const void *buffer, unsigned length)
{
  is_pointer_valid ((uint32_t *) buffer);

  lock_acquire (&file_lock);
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, length);
    }

  lock_release (&file_lock);
  return ERROR_RET_STATUS;
}

/* */
static int
syscall_filesize (int fd)
{
  int file_size;
  lock_acquire (&file_lock);
  //int file_size = (int) file_length (thread_current ()->fd_map [fd]);
  lock_release (&file_lock);
  return file_size;
}
















