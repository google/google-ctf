// Copyright 2020 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Ian Eldred Pudney
#ifndef EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SHARED_H_
#define EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SHARED_H_

#include <pthread.h>
#include <sys/ucontext.h>
#include <deque>
#include <vector>
#include <atomic>
#include <string>
#include <functional>
#include <unistd.h>

inline std::vector<pthread_t>& native_threads = *new std::vector<pthread_t>();
inline std::atomic<pthread_t> guard_var = 0;
// FIFO queue of threads that are not blocked, but not currently scheduled on
// any underlying native thread.
inline std::deque<ucontext_t*>& ready_queue = *new std::deque<ucontext_t*>();

constexpr auto stack_size = 4096 * 64;

// Data about the current native thread, because pthread_self() has locking that
// might be preempted, which casues deadlock if accessed both within and without
// a critical section.
inline thread_local pthread_t current_thread = -1;
inline thread_local int current_thread_idx = -1;

// Allocate a stack for a thread.
void* alloc_stack();

// Free a stack for a thread allocated with alloc_stack.
void free_stack(void* stack);

// Sets the maximum number of native threads to use. Until this number is
// reached, new threads will be backed by a native thread. Once this number
// is reached, native threads will start to be shared. May not be called after
// threads have been created.
void set_max_native_threads_impl(int threads);

// Disables preemption and grabs the guard.
void enter_critical_section();

// Releases the guard and enables preemption.
void leave_critical_section();

// Acquires the guard.
void acquire_guard();

// Releases the guard.
void release_guard();

// TODO: REMOVE ALL ASSERTIONS TO MAKE EXPLOITATION EASY
// Assert that this native thread holds the guard.
void assert_guard_held();

// Assert that this native thread does not hold the guard.
void assert_guard_not_held();

// Get the current native thread name.
std::string native_thread_name(pthread_t thread = pthread_self());

// Ends the current thread. Swaps to a thread on the ready queue, or halts
// otherwise. Takes the stack of the current thread, to queue its deletion.
void end_thread(void* stack_to_delete);

// Performs any cleanup requested by the from-thread. To be called immediately
// after returning from a context switch.
void cleanup_after_switch();

// Request some cleanup after the next context switch.
void add_pending_cleanup(std::function<void()> cb);

// Puts the current thread onto destination_queue. Then, swaps to a thread on
// the ready queue, or if no threads are available to run, suspends the current
// native thread.
// Note that destination_queue might be the ready queue, in which case the
// current thread isn't actually "blocked", and becomes immediately eligible to
// run again.
void block_thread(std::deque<ucontext_t*>* destination_queue);

// Makes the specified thread ready to run. Has the following priority:
//  - If there are any halted native threads, wakes them up and readies this.
//  - If there are any unstarted native threads, starts them and gives them this
//  - Puts this on the ready queue (and starts the preemptifier if not started)
void ready_thread(ucontext_t* ctx);

#endif  // EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SHARED_H_
