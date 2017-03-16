#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <hash.h>
#include <stdint.h>
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/*Macros for advanced scheduler*/
#define DEFAULT_NICE 0
#define MIN_NICE -20
#define MAX_NICE 20
#define DEFAULT_RECENT_CPU 0

/* Macros for userprog */
#ifdef USERPROG
#define DEFAULT_RET_STATUS 0
#define ERROR_RET_STATUS -1
#endif

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    int base_priority;                  /* Used to reset to original priority */
    struct lock *waiting_lock;          /* The lock that the current thread is
                                           waiting for */
    struct list holding_locks;          /* List of locks that the thead holds */
    struct list_elem allelem;           /* List element for all threads list. */

    int nice;                           /*Niceness value of thread*/
    int32_t recent_cpu;                 /*CPU time allocated*/

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct list open_files;             /* A mapping from fd to a file */
    int last_fd;                        /* Used to describe next avaliable fd */

    struct list executing_children;     /* Keeps a reference to all executing_children */
    struct list finished_children;      /* Keeps a reference to all finished_children */
    struct thread *parent;              /* Reference to parent process */
    struct semaphore sema_wait;         /* Semaphore used by process_wait */
    struct semaphore sema_load;         /* Secures successful loading */
    struct list_elem exec_children_elem;     /* Used by children list */
    struct file *deny_file;             /* Used by denying writes to executables feature */
    bool has_waited;                    /* Parent process called wait */
    bool has_loaded;                    /* If child has loaded succsefully */
    int return_status;                  /* The process exit status */
#endif

#ifdef VM
    struct hash page_table;
    int last_vm_file_map;
#endif

    int64_t wake_up_tick;               /* To monitor of sleep_time */
    struct list_elem sleeping_thread;   /* Add to sleeping_thread_list when
                                           calling timer_sleep*/
    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* Used by process to idnetify executed process return status */
struct fin_process_map
  {
    tid_t tid;               /* Process idnetifier */
    int return_status;       /* The return status */
    bool has_waited;         /* Parent process called wait */
    bool has_loaded;
    struct list_elem elem;
  };

/* Used by the process mapping of open files */
struct file_map
  {
    int fd;
    struct file *f;
    struct list_elem elem;
  };

/* Initial thread, the thread running init.c:main(). */
struct thread *initial_thread;

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);
struct thread *get_thread_from_tid (tid_t tid);
struct thread *get_exec_children (tid_t tid);
struct fin_process_map *get_finished_children (tid_t tid);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

void reset_thread_ready_list (struct thread *t);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

void thread_compute_load_avg (void);
void thread_compute_recent_cpu (struct thread *t, void *aux UNUSED);
int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
