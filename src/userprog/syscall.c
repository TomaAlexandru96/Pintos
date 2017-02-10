#include <syscall-nr.h>
#include "userprog/syscall.h"
#include <stdio.h>
#include "threads/interrupt.h"
#include "userprog/process.h"
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
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static void halt (void);
static void exit (int status);
static pid_t exec (const char *file);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

static struct lock file_lock;
typedef int (*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_map[32];

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  //uncomment after implementing whole syscall handler
  syscall_map[SYS_HALT]     = (handler)halt;
  syscall_map[SYS_EXIT]     = (handler)exit;
  //syscall_map[SYS_EXEC]     = (handler)exec;
  syscall_map[SYS_WAIT]     = (handler)wait;
  //syscall_map[SYS_CREATE]   = (handler)create;
  //syscall_map[SYS_REMOVE]   = (handler)remove;
  //syscall_map[SYS_OPEN]     = (handler)open;
  //syscall_map[SYS_FILESIZE] = (handler)filesize;
  //syscall_map[SYS_READ]     = (handler)read;
  syscall_map[SYS_WRITE]    = (handler)write;
  //syscall_map[SYS_SEEK]     = (handler)seek;
  //syscall_map[SYS_TELL]     = (handler)tell;
  //syscall_map[SYS_CLOSE]    = (handler)close;

  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  handler function;
  int *parameter = f->esp, ret;

  if ( is_user_vaddr(parameter) == -1)
    {
      exit(ERROR_RET_STATUS);
    }

  if (!( is_user_vaddr (parameter + 1) && is_user_vaddr (parameter + 2)
      && is_user_vaddr (parameter + 3)))
    {
      exit(ERROR_RET_STATUS);
    }

  if (*parameter < SYS_HALT || *parameter > SYS_INUMBER)
    {
      exit(ERROR_RET_STATUS);
    }

  function = syscall_map[*parameter];

  ret = function (*(parameter + 1), *(parameter + 2), *(parameter + 3));
  f->eax = ret;

  return;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  //if (f->h) {
  //
  //}
  printf ("system call!\n");
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Halt the OS. */
static void
halt (void)
{
  shutdown_power_off ();
}

/* Terminate the user process. */
static void
exit (int status)
{
  struct thread *t;

  t = thread_current ();
  // Implement close files

  t->return_status = status;
  thread_exit ();
  return -1;
}

/* Wait for child process to finish. */
static int
wait (pid_t pid)
{
  return process_wait (pid);
}

/* Writing to file. */
static int
write (int fd, const void *buffer, unsigned length)
{
  struct file *f;

  lock_acquire (&file_lock);
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, length);
    }
  else if (fd == STDIN_FILENO)
      ;
  else if ( !is_user_vaddr (buffer) || !is_user_vaddr (buffer + length) )
    {
      lock_release (&file_lock);
      exit (-1);
    }
  else
    {
      //Implement writing to file
    }

  lock_release (&file_lock);
  return ERROR_RET_STATUS;
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
  : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
  : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
