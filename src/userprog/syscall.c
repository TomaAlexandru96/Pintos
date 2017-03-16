#include <syscall-nr.h>
#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "threads/malloc.h"
#include <stdio.h>
#include <list.h>
#include <inttypes.h>

#define ARGUMENTS_IN_USER_SPACE(intr_frame, param_nr) do \
  {is_pointer_valid (((uint32_t *) intr_frame->esp)      \
    + param_nr, intr_frame);} while (0)
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
static void syscall_mmap (struct intr_frame *);
static void syscall_munmap (struct intr_frame *);

static bool remove_fd (int fd);
static struct file_map *get_filemap (int fd);
static void is_pointer_valid (const void *param, struct intr_frame *);
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
  syscall_map[SYS_MMAP]     = syscall_mmap;
  syscall_map[SYS_MUNMAP]   = syscall_munmap;

  lock_init (&file_lock);
}

static void
is_pointer_valid (const void *param, struct intr_frame *f UNUSED)
{
  lock_acquire (&file_lock);
  if (page_get_data (pg_round_down (param)) != NULL)
    {
      int i = * (int *) param;
      if (i == 0)
        {
          barrier ();
        }
    }
  if (!is_user_vaddr (param) || (pagedir_get_page (thread_current ()->pagedir,
                                                  param) == NULL))
    {
      lock_release (&file_lock);
      syscall_exit_aux (f, -1);
    }
  lock_release (&file_lock);
}

static struct file_map *
get_filemap (int fd)
{
  struct list_elem *e;

  for (e = list_begin (&thread_current ()->open_files);
       e != list_end (&thread_current ()->open_files);
       e = list_next (e))
    {
      struct file_map *file_m = list_entry (e, struct file_map, elem);
      if (file_m->fd == fd)
        return file_m;
    }

  return NULL;
}

static bool
remove_fd (int fd)
{
  if (fd >= thread_current ()->last_fd) {
    return false;
  }

  struct file_map *m = get_filemap (fd);

  if (m == NULL)
    {
      return false;
    }

  list_remove (&m->elem);

  return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  thread_current ()->esp = (uint32_t) f->esp;
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

  f->eax = status;
  t->return_status = status;

  thread_exit ();
}

/* Wait for child process to finish. */
static void
syscall_wait (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int pid = (int) GET_ARGUMENT (f, 1);

  f->eax = (uint32_t) process_wait (pid);
}

static void
syscall_tell (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int fd = GET_ARGUMENT (f, 1);

  struct file_map *m = get_filemap (fd);

  if (m == NULL)
    {
      // ERROR
      return;
    }

  lock_acquire (&file_lock);
  off_t offset = file_tell (m->f);
  lock_release (&file_lock);

  f->eax = (uint32_t) offset;
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
  const char *buffer = (const char *) GET_ARGUMENT (f, 2);
  unsigned length = (unsigned) GET_ARGUMENT (f, 3);
  is_pointer_valid (buffer, f);
  is_pointer_valid (buffer + length - 1, f);

  lock_acquire (&file_lock);

  uint32_t size_written = 0;

  if (fd == STDOUT_FILENO)
    {
      size_written = length;
      putbuf (buffer, length);
    }
  else if (fd == STDIN_FILENO)
    {
      lock_release (&file_lock);
      syscall_exit_aux (f, -1);
      return;
    }
  else
    {
      struct file_map *m = get_filemap (fd);

      if (m == NULL)
        {
          lock_release (&file_lock);
          syscall_exit_aux (f, -1);
          return;
        }
      size_written = (uint32_t) file_write (m->f, buffer, length);
    }
  lock_release (&file_lock);

  f->eax = size_written;
}

/* */
static void
syscall_filesize (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int fd = (int) GET_ARGUMENT (f, 1);

  struct file_map *m = get_filemap (fd);

  if (m == NULL)
    {
      // ERROR
      return;
    }

  lock_acquire (&file_lock);
  int file_size = (int) file_length (m->f);
  lock_release (&file_lock);
  f->eax = file_size;
}

/*  */
static void
syscall_open (struct intr_frame *frame UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (frame, 1);
  const char *file = (const char *) GET_ARGUMENT (frame, 1);

  is_pointer_valid ((uint32_t *) file, frame);

  int fd = thread_current ()->last_fd;
  lock_acquire (&file_lock);
  struct file *f = filesys_open (file);
  lock_release (&file_lock);
  if (f == NULL)
    {
      frame->eax = -1;
      return;
    }
  struct file_map *fm = (struct file_map *) malloc (sizeof (struct file_map));
  fm->fd = fd;
  fm->f = f;
  list_push_back (&thread_current ()->open_files, &fm->elem);
  thread_current ()->last_fd++;
  frame->eax = fd;
}

static void
syscall_exec (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  const char *cmd = (const char *) GET_ARGUMENT (f, 1);
  is_pointer_valid ((uint32_t *) cmd, f);

  tid_t tid = process_execute (cmd);

  if (tid == TID_ERROR)
    {
      f->eax = -1;
    }
  else
    {
      f->eax = tid;
    }
}

static void
syscall_remove (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  const char *file = (const char *) GET_ARGUMENT (f, 1);

  lock_acquire (&file_lock);
  bool ret = filesys_remove (file);
  lock_release (&file_lock);

  f->eax = (uint32_t) ret;
}

static void
syscall_read (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 3);
  int fd = (int) GET_ARGUMENT (f, 1);
  void *buffer = (void *) GET_ARGUMENT (f, 2);
  unsigned size = (unsigned) GET_ARGUMENT (f, 3);
  is_pointer_valid (buffer, f);
  is_pointer_valid (buffer + size - 1, f);

  struct file_map *m = get_filemap (fd);

  if (m == NULL)
    {
      // ERROR
      return;
    }

  struct file *file = m->f;
  lock_acquire (&file_lock);
  off_t offset = file_read (file, buffer, size);
  lock_release (&file_lock);
  f->eax = (uint32_t) offset;
}

static void
syscall_seek (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 2);
  int fd = (int) GET_ARGUMENT (f, 1);
  unsigned position = (unsigned) GET_ARGUMENT (f, 2);

  struct file_map *m = get_filemap (fd);

  if (m == NULL)
    {
      // ERROR
      return;
    }

  struct file *file = m->f;

  lock_acquire (&file_lock);
  file_seek (file, (off_t) position);
  lock_release (&file_lock);
}

static void
syscall_close (struct intr_frame *f UNUSED)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int fd = (int) GET_ARGUMENT (f, 1);

  struct file_map *fm = get_filemap (fd);
  syscall_close_aux (fm);
  free (fm);
}

void
syscall_close_aux (struct file_map *fm)
{
  if (fm == NULL)
    {
      // ERROR
      return;
    }

  struct file *file = fm->f;
  lock_acquire (&file_lock);
  file_close (file);
  lock_release (&file_lock);

  bool has_been_removed = !remove_fd (fm->fd);

  if (!has_been_removed)
    {
      // ERROR
    }
}

static void
syscall_mmap (struct intr_frame *f)
{
  ARGUMENTS_IN_USER_SPACE (f, 2);
  int fd = (int) GET_ARGUMENT (f, 1);
  void *addr = (void *) GET_ARGUMENT (f, 2);
  struct file_map *m = get_filemap (fd);
  if (m == NULL)
    {
      f->eax = -1;
      return;
    }
  lock_acquire (&file_lock);
  int file_size = (int) file_length (m->f);
  if (file_size == 0 || addr == 0 || fd == 0 || fd == 1 || pg_ofs (addr) != 0)
    {
      f->eax = -1;
      lock_release (&file_lock);
      return;
    }
  int no_pages = file_size / PGSIZE;
  if (file_size % PGSIZE != 0)
    {
      no_pages++;
    }
  for (int i = 0; i < no_pages; i++)
    {
      if (page_get_data ((void *) ((int) addr + PGSIZE*i)) != NULL)
        {
          f->eax = -1;
          lock_release (&file_lock);
          return;
        }
    }

  for (int i = 0; i < no_pages; i++)
    {
      struct page_table_entry *entry = page_insert_data ((void *) ((int) addr +
                                       PGSIZE*i));
      entry->l = FILE_SYS;
      entry->mapping_index = i;
      entry->f = m->f;
      entry->map_id = thread_current ()-> last_vm_file_map;
    }
  f->eax = thread_current ()-> last_vm_file_map;
  thread_current ()-> last_vm_file_map++;
  lock_release (&file_lock);
}


static void
syscall_munmap (struct intr_frame *f)
{
  ARGUMENTS_IN_USER_SPACE (f, 1);
  int mapping_id = (int) GET_ARGUMENT (f, 1);

  syscall_munmap_aux (mapping_id);
}

void
syscall_munmap_aux (int map_id)
{
  void *removed_mapps[hash_size (&thread_current ()->page_table)];
  struct hash_iterator it;
  int index = 0;

  hash_first (&it, &thread_current ()->page_table);
  while (hash_next (&it))
    {
      struct page_table_entry *pt_entry =
              hash_entry (hash_cur (&it), struct page_table_entry, hash_elem);

      if (pt_entry->f != NULL && pt_entry->map_id == map_id)
        {
          removed_mapps[index] = pt_entry->pg_addr;
          index++;
        }
    }

  for (int i = 0; i < index; i++)
    {
      page_remove_data (removed_mapps[i]);
    }
}
