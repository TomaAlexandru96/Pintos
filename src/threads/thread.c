#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "devices/timer.h"
#include "threads/fixed-point.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "userprog/pagedir.h"
#endif
#ifdef VM
#include "vm/page.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* System load average */
static int32_t load_avg;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
static list_less_func priority_queue_sort;
static list_less_func compare_thread_priority;

/*Calculates thread priority for bsd scheduler*/
static void compute_bsd_priority (struct thread *t, void *aux UNUSED);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void)
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();

  #ifdef USERPROG
  list_init (&initial_thread->executing_children);
  list_init (&initial_thread->finished_children);
  sema_init (&initial_thread->sema_wait, 0);
  initial_thread->last_vm_file_map = 1;
  initial_thread->fault_esp = NULL;
  #endif
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void)
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /*If mlfqs is true and current thread not idle, increment recent_cpu*/
  if (thread_current () != idle_thread && thread_mlfqs)
    {
  	  t->recent_cpu = add_fp_and_int(t->recent_cpu, 1);
    }

  /* Recompute recent cpu and load_avg every second */
  if (thread_mlfqs && timer_ticks () % TIMER_FREQ == 0)
    {
    	thread_compute_load_avg ();
    	thread_foreach (&thread_compute_recent_cpu, NULL);
    }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    {
      /*Recompute all priorities if mlfqs is true*/
      if (thread_mlfqs)
        {
         thread_foreach (&compute_bsd_priority, NULL);
        }

      intr_yield_on_return ();
    }
}

/* Prints thread statistics. */
void
thread_print_stats (void)
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack'
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  #ifdef USERPROG
  t->last_fd = 2;
  list_init (&t->open_files);
  list_init (&t->executing_children);
  list_init (&t->finished_children);
  sema_init (&t->sema_load, 0);
  sema_init (&t->sema_wait, 0);
  t->has_waited = false;
  t->parent = thread_current ();
  #endif

  #ifdef VM
  hash_init (&t->page_table, &page_hash_func, &page_less_func, NULL);
  t->last_vm_file_map = 1;
  t->fault_esp = NULL;
  #endif

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);

  if (t->priority > thread_current ()->priority)
    {
      thread_yield ();
    }

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void)
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t)
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  /* Insert thread t in the ready_list based on it's priority */
  list_insert_ordered (&ready_list, &t->elem, &priority_queue_sort, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void)
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void)
{
  struct thread *t = running_thread ();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void)
{
  return thread_current ()->tid;
}

struct thread *
get_exec_children (tid_t child_tid)
{
  struct list_elem *e;

  for (e = list_begin (&thread_current ()->executing_children);
       e != list_end (&thread_current ()->executing_children);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, exec_children_elem);
      if (t->tid == child_tid)
        {
          return t;
        }
    }
  return NULL;
}

struct fin_process_map *
get_finished_children (tid_t child_tid)
{
  struct list_elem *e;

  for (e = list_begin (&thread_current ()->finished_children);
       e != list_end (&thread_current ()->finished_children);
       e = list_next (e))
    {
      struct fin_process_map *m = list_entry (e, struct fin_process_map, elem);
      if (m->tid == child_tid)
        {
          return m;
        }
    }
  return NULL;
}

/*
  Returns the thread given the tid from list of all threads
*/
struct thread *
get_thread_from_tid (tid_t tid)
{
  struct list_elem *e;

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      if (t->tid == tid)
        return t;
    }

  return NULL;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void)
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread)
    {
      list_insert_ordered (&ready_list, &cur->elem,
            &priority_queue_sort, NULL);
    }
  cur->status = THREAD_READY;
  /* Go in the scheduler and make the highest priority thread run */
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, UNUSED void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* A comparator function used when inserting in a list based on priority.
   The insertion is made in ascendant order based on the value of priority. */
static bool
priority_queue_sort (const struct list_elem *a,
                     const struct list_elem *b,
                     void *aux UNUSED)
{
  struct thread *a_thread = list_entry (a, struct thread, elem);
  struct thread *b_thread = list_entry (b, struct thread, elem);
  return a_thread->priority > b_thread->priority;
}

/* Compares priority of 2 threads in ready_list.
   Returns true if tread b has higher priority than thread a, false otherwise.*/
static bool
compare_thread_priority (const struct list_elem *a,
                    	 const struct list_elem *b,
                    	 void *aux UNUSED)
{
  struct thread *a_thread, *b_thread;
  a_thread = list_entry (a, struct thread, elem);
  b_thread = list_entry (b, struct thread, elem);

  return a_thread->priority < b_thread->priority;
}

/* Called when a thread t changes priority and you want to still be at the
   right position within the ready_list. */
void
reset_thread_ready_list (struct thread *t)
{
  list_remove (&t->elem);
  /* Insert back in the ready_list thread t. */
  list_insert_ordered (&ready_list, &t->elem, &priority_queue_sort, NULL);
  /* Checks if thread t is still the one with highest priority. */
  if (t->priority > thread_current ()->priority) {
    thread_yield ();
  }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority)
{
  if (thread_mlfqs)
    {
      thread_current ()->priority = new_priority;
      return;
    }

  /* When we are dealing with a donation */
  if (thread_current ()->priority != thread_current ()->base_priority)
    {
      /* If the new_priority is bigger than priority, set it to new_priority. */
      if (thread_current ()->priority < new_priority)
        {
          thread_current ()->priority = new_priority;
        }
    }
  else
    {
      thread_current ()->priority = new_priority;
    }
  thread_current ()->base_priority = new_priority;

  /* Check if new_priority is no longer the biggest priority by comparing it
     with the maximum value from the ready_list. */
  enum intr_level old_level = intr_disable ();
  if (!list_empty (&ready_list) && new_priority <
        list_entry (list_front (&ready_list), struct thread, elem)->priority)
    {
      thread_yield ();
    }
  intr_set_level (old_level);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void)
{
  return thread_current ()->priority;
}

/* Computes thread priorities for the bsd schduler based on the formula:
   bsd_priority = PRI_MAX - (recent_cpu / 4) - (nice * 2) */
void
compute_bsd_priority (struct thread *t, void *aux UNUSED)
{
  ASSERT (thread_mlfqs);
  int32_t max_priority = int_to_fp (PRI_MAX);
  int32_t recent_cpu = divide_fp_by_int (t->recent_cpu, 4);
  max_priority = subtract_fp (max_priority, recent_cpu);
  max_priority = subtract_fp (max_priority, int_to_fp (t->nice * 2));
  int int_rounded_priority = fp_to_int_round_towards_zero (max_priority);

  /* If the rounded priority is bigger than the maximum value allowed, set it to
     the max priority allowed (63). */
  if (int_rounded_priority > PRI_MAX)
    {
      int_rounded_priority = PRI_MAX;
    }

  /* If the rounded priority is smaller than the minimum value allowed, set it
     to the min priority allowed (0). */
  if (int_rounded_priority < PRI_MIN)
    {
      int_rounded_priority = PRI_MIN;
    }
  t->priority = int_rounded_priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED)
{
  ASSERT (thread_mlfqs);
  ASSERT (nice >= MIN_NICE);
  ASSERT (nice <= MAX_NICE);
  thread_current ()->nice = nice;
  compute_bsd_priority(thread_current (), NULL);

  if (!list_empty(&ready_list))
    {
      struct thread * next_thread = list_entry (list_max (&ready_list,
                          &compare_thread_priority, NULL), struct thread, elem);
      /* If the current thread is no longer the one with the highest priority
         yield and change the current running thread. */
      if(thread_current ()->priority < next_thread->priority)
        thread_yield ();
    }
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void)
{
  ASSERT (thread_mlfqs);
  return thread_current ()->nice;
}

/* Computes current load_avg:
   load_avg = (59/60)*load_avg + (1/60)*ready_threads */
void
thread_compute_load_avg (void)
{
  int32_t load_avg_factor = int_to_fp (59);
  load_avg_factor = divide_fp_by_int (load_avg_factor, 60);
  int32_t ready_thread_factor = int_to_fp (1);
  ready_thread_factor = divide_fp_by_int (ready_thread_factor, 60);
  int ready_threads = list_size (&ready_list);
  if (thread_current () != idle_thread)
    ready_threads++;

  load_avg_factor = multiply_fp (load_avg_factor, load_avg);
  ready_thread_factor = multiply_fp_and_int (ready_thread_factor, ready_threads);

  load_avg = add_fp (load_avg_factor, ready_thread_factor);
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void)
{
  int32_t curr_load_avg = load_avg;
  int round_load_avg;
  curr_load_avg = multiply_fp_and_int (curr_load_avg, 100);
  round_load_avg = fp_to_int_round_to_nearest (curr_load_avg);
  return round_load_avg;
}

/* Computes recent cpu usage:
   recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice */
void
thread_compute_recent_cpu (struct thread *t, void *aux UNUSED)
{
  int32_t recent_cpu = t->recent_cpu;
  int32_t curr_load_avg = load_avg;
  int32_t coefficient;
  curr_load_avg = multiply_fp_and_int (curr_load_avg, 2);
  coefficient = divide_fp (curr_load_avg, add_fp_and_int (curr_load_avg, 1));
  recent_cpu = multiply_fp (coefficient, recent_cpu);
  recent_cpu = add_fp_and_int (recent_cpu, t->nice);
  t->recent_cpu = recent_cpu;
}

/* Returns 100 times the current thread's recent_cpu value. */

int
thread_get_recent_cpu (void)
{
  int32_t curr_recent_cpu = thread_current ()->recent_cpu;
  int round_recent_cpu;
  curr_recent_cpu = multiply_fp_and_int (curr_recent_cpu, 100);
  round_recent_cpu = fp_to_int_round_to_nearest (curr_recent_cpu);
  return round_recent_cpu;
}


/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;)
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux)
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;

  /*Set initial nice and recent_cpu values to 0*/
  t->nice = DEFAULT_NICE;
  t->recent_cpu = DEFAULT_RECENT_CPU;

  t->magic = THREAD_MAGIC;

  /* If thread_mlfqs true compute_bsd priority */
  if (thread_mlfqs)
    {
      compute_bsd_priority (t, NULL);
    }
  else
    {
	    t->priority = priority;
	    t->base_priority = priority;
      list_init (&t->holding_locks);
    }

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void)
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();

  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void)
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
