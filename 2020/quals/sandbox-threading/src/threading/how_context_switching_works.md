# How Context Switching Works

This document describes how this thread library switche between userland threads. Pthreads are used as an underlying thread primitive, and usrrland threads are switched between them. One userland thread might be run on a pthread, get preempted, and later be scheduled on a different pthread.

## Understanding the `ucontext_t`

The information about a userland thread's state is stored in a POSIX structure called a `ucontext_t`. The contents of this structure are implementation-defined, but it stores all the information needed to descibe a thread, including its registers, program counter, and pointer to its stack.

#### Switching Contexts

POSIX provides a few functions for working with contexts. Notable functions include:

* `getcontext`: Save a snapshot of the current thread's registers, program counter, etc. into the specified context. If this context is loaded via `setcontext`, execution will pick up immediately after the `getcontext` call.
 * `setcontext`: Load the specified context, and start executing it. This means the current native thread will no longer be doing whatever it was doing before; this function does not return. Instead, the current native thread will be executing whatever was stored in the specified context.
 * `swapcontext`: a combination of `getcontext` and `setcontext`. Stores the current thread's state into one of the specified contexts, and loads the other context. If the new stored context is later loaded via `setcontext`, execution will resume after `swapcontext`.
 * `makecontext`: This takes a function pointer as an argument and synthetically creates a new context such that the specified function will be executed when the context is loaded.

In this threading library, `makecontext` is used for the creation of new userland threads. `swapcontext` is not used; rather, `getcontext` and `setcontext` are used directly. While this pattern is spread across multiple functions in this library, the following is a possible implementation of `swapcontext` in terms of `getcontext` and `setcontext`:

```
void swapcontext(ucontext_t* out, ucontext_t* in) {
    volatile bool first_pass_done = false;
    getcontext(out);
    if (!first_pass_done) {
        first_pass_done = true;
        setcontext(in);
    }
}
```

#### Thread Termination

The final act of any thread is to `setcontext` to a new thread. The thread leaves a Last Will and Testament behind, specifying how to dispose of its estate. (In other words: It registers a cleanup routine, which the switched-to thread will execute. This routine specifies how to delete its stack and such.)

## Scheduling

If all threads could run all the time, there would be no need for context switching. But, that's not always the case. Some threads might be blocked, or there might just be too many threads and not enough pthreads.

To solve this problem, we have queues. First, there's the ready queue. This contains the contexts of threads that aren't blocked on anything, but aren't currently running because all pthreads are busy.

Then, there are blocking queues. Each semaphore has its own blocking queue, as does each thread (used for `join`). If a thread `join`s another running thread or `down`s a semaphore that's already 0, the thread will push its context onto the appropriate blocking queue, then pop a thread off the ready queue and `setcontext` to it.

When a thread is terminated, it loads a new thread using `setcontext` without pushing its own context onto any queue.

#### Preemption

Sometimes, there are too many threads. To solve this problem, this threading library uses a background pthread whose purpose is to send signals to the other threads. When a thread receives such a signal, it immediately stops what it's doing and goes through the queuing process described above. The difference is, the thread's still ready, so it pushes its context onto the back of the ready queue rather than onto the back of some blocking queue.

When the preempted thread is eventually loaded again, it will continue and return from its signal handler. This will then cause it to resume execution where it left offr.

#### Suspension

Sometimes, the threading library has the opposite problem: it has too many pthreads and not enough userland threads to use them. When this occurs, the threading library needs to put that pthread to sleep. It does this with `sigsuspend`. The thread will stay suspended until the number of ready threads increases in the future (this can happen either because a new thread is created, or an existing thread is unblocked). When this occurs, one sleeping pthread will be awoken with a signal, and will switch to the new thread.

Between preemption and suspension, both `SIGUSR1` and `SIGUSR2` are used by the library. Do not be alarmed if your debugger stops upon receiving these signals. If using GDB, you can filter them out with:

```
handle SIGUSR1 nostop noprint
handle SIGUSR2 nostop noprint
```

## Atomicity

The threading library implements atomic scheduling primitives (semaphores). Obviously, this means it can't use those primitives in its own construction, but still needs to be atomic. Only one thread is permitted to execute threading-library code at once. But how is this enforced?

There are two key mechanisms: 
 * an atomic guard variable
 * a signal mask

The atomic guard variable is used as a spinlock: it's acquired when a thread enters the threading library, and released when it exits; other threads will spin until it's released, and can then grab it.

The signal mask is used to prevent preemption signals from being received while already in the threading library.

#### Incompatibility with pthread locking mechanisms

This scheme is (somewhat) incompatible with other locking mechanisms. In particular, no other locking mechanism may be used both inside and outside of the threading library. Note that **`cout` and `cerr` use locks.** This means that if you add debugging prints inside the threading library, but also have prints outside the threading library, you might deadlock. 

Why? Well, consider the following ordering:

```
thread 1 calls cout << "foo" outside the library
thread 1 grabs the stdout lock
thread 2 calls sem.up();
thread 2 grabs the guard
thread 2 calls cout << "bar" inside the library
thread 2 waits on the stdout lock
thread 1 gets preempted
thread 1 waits on the guard
```

You now have a deadlock between the guard and the stdout lock.

Printing just outside the threading library is fine, as is printing just inside the threading library. Using both is not.

#### But why semaphores? Where's `mutex` and `condition_variable`?

Semaphores are great. They're the Turing machines of synchronization primitives: with semaphores, you can synchronize anything that can be synchronized.

Mutexes by themselves cannot do that; however, mutexes + condition variables can. I leave it as an exercise to the reader to implement `mutex` and `condition_variable` using `semaphore`s, and then to implement `semaphore` using `mutex`es and `condition_variable`s.

