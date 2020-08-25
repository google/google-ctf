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
#include "shared.h"
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <array>
#include <iostream>
#include <thread>
#include "signals.h"
#include "thread.h"

namespace {

thread_local std::vector<std::function<void()>> cleanups;
bool native_threads_locked = false;
bool preemptifier_started = false;
int max_native_threads = 1;
// FIFO queue of native threads that are currently suspended because there is
// no work to do.
std::deque<pthread_t>& halted_native_threads = *new std::deque<pthread_t>();

void start_native_thread(ucontext_t* ctx) {
  assert_guard_held();
  assert_preemption_disabled();

  int thread_num = native_threads.size();
  native_threads.emplace_back();
  std::thread t([ctx, thread_num]() {
    // A new thread inherits a copy of its parent's signal mask, so preemption
    // starts disabled.
    assert_preemption_disabled();
    assert_guard_not_held();

    current_thread = pthread_self();
    current_thread_idx = thread_num;

    acquire_guard();

    setcontext(ctx);
  });

  pthread_t new_thread = t.native_handle();
  native_threads[thread_num] = new_thread;

  std::string thread_name = "native_thread_" + std::to_string(thread_num);
  pthread_setname_np(new_thread, thread_name.c_str());

  t.detach();
}

std::vector<void*>& free_stacks = *new std::vector<void*>();

} // namespace

// Allocate a stack for a thread.
void* alloc_stack() {
  if (!free_stacks.empty()) {
    void* ret = free_stacks.back();
    free_stacks.pop_back();
    return ret;
  }

  void* region = mmap(nullptr, stack_size + (2 * 4096), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);

  // Make the first and last pages guard pages.
  mprotect(region, 4096, PROT_NONE);
  mprotect(reinterpret_cast<char*>(region) + stack_size + 4096, 4096, PROT_NONE);

  // Put the stack in the unprotected part of the region.
  return reinterpret_cast<char*>(region) + 4096;
}

// Free a stack for a thread allocated with alloc_stack.
void free_stack(void* stack) {
  free_stacks.push_back(stack);
}

void set_max_native_threads_impl(int threads) {
  if (native_threads_locked) {
    std::cerr << "Cannot set_max_native_threads after threads have been created." << std::endl;
    _exit(1);
  }
  max_native_threads = threads;
}

void acquire_guard() {
  assert_guard_not_held();

  pthread_t desired = current_thread;
  while (true) {
    pthread_t expected = 0;
    guard_var.compare_exchange_weak(expected, desired);
    if (!expected) break;  // If expected is still 0, we've got the guard.
  }
}

void release_guard() {
  assert_guard_held();

  guard_var = 0;
}

// Disables preemption and grabs the guard.
void enter_critical_section() {
  assert_guard_not_held();
  assert_preemption_enabled();

  disable_preemption();
  acquire_guard();
  assert_guard_held();
}

// Releases the guard and enables preemption.
void leave_critical_section() {
  assert_guard_held();
  assert_preemption_disabled();

  release_guard();
  enable_preemption();
}

// Assert that this thread holds the guard.
void assert_guard_held() {
  pthread_t guard_value = guard_var;
  if (guard_value != current_thread) {
    std::cerr << "Thread " << current_thread_idx << " thinks it has the guard, but the guard is held by " << std::flush << guard_value << "[" << native_thread_name(guard_value) << "]" << std::endl;
    _exit(1);
  }
}

// Assert that this thread does not hold the guard.
void assert_guard_not_held() {
  pthread_t guard_value = guard_var;
  if (guard_value == current_thread) {
    std::cerr << "Thread " << current_thread_idx << " thinks it shouldn't have the guard, but it does." << std::endl;
    _exit(1);
  }
}

std::string native_thread_name(pthread_t thread) {
  char buf[129];
  buf[128] = 0;
  pthread_getname_np(thread, buf, 128);
  return std::string(buf);
}

void suspend_thread(void* buf) {
  while (ready_queue.empty()) {
    // There's nothing ready to run, we need to go to sleep.
    halted_native_threads.push_back(current_thread);

    if (halted_native_threads.size() == native_threads.size()) {
      std::cerr << "Deadlock detected; no runnable threads." << std::endl;
      _exit(1);
    }

    release_guard();
    halt();
    acquire_guard();
  }

  // There's another thread ready to run
  ucontext_t* new_ctx = ready_queue.front();
  ready_queue.pop_front();
  add_pending_cleanup([new_ctx]() {
    delete new_ctx;
  });
  setcontext(new_ctx);
}

void suspend_thread_rec() {
  std::array<int, 128> arr;
  suspend_thread((void*)arr.data());
}

void block_thread(std::deque<ucontext_t*>* destination_queue) {
  assert_guard_held();
  assert_preemption_disabled();
  ucontext_t* self_ctx = new ucontext_t();
  destination_queue->push_back(self_ctx);

  volatile bool context_restored = false;
  getcontext(self_ctx);
  if (context_restored) {
    cleanup_after_switch();
    return;
  }
  context_restored = true;

  suspend_thread_rec();
}

// Performs any cleanup requested by the from-thread. To be called immediately
// after returning from a context switch.
void cleanup_after_switch() {
  assert_guard_held();
  assert_preemption_disabled();
  for (const auto& cleanup : cleanups) {
    cleanup();
  }
  cleanups.clear();
}

// Request some cleanup after the next context switch.
void add_pending_cleanup(std::function<void()> cb) {
  assert_guard_held();
  assert_preemption_disabled();
  cleanups.push_back(cb);
}

void end_thread(void* stack_to_delete) {
  assert_guard_held();
  assert_preemption_disabled();

  while (ready_queue.empty()) {
    halted_native_threads.push_back(current_thread);

    if (halted_native_threads.size() == native_threads.size()) {
      std::cerr << "Deadlock detected; no runnable threads." << std::endl;
      _exit(1);
    }

    release_guard();
    halt();
    acquire_guard();

  }

  ucontext_t* from_ctx = ready_queue.front();
  ready_queue.pop_front();
  add_pending_cleanup([from_ctx]() {
    delete from_ctx;
  });
  add_pending_cleanup([stack_to_delete]() {
    free_stack(stack_to_delete);
  });
  setcontext(from_ctx);
}

void ready_thread(ucontext_t* ctx) {
  assert_guard_held();
  assert_preemption_disabled();

  if (!native_threads_locked) {
    // We are creating our first thread. Register the main thread.
    native_threads_locked = true;
    current_thread = pthread_self();
    current_thread_idx = 0;
    native_threads.push_back(current_thread);
    std::string thread_name = "native_thread_0";
    pthread_setname_np(current_thread, thread_name.c_str());
    guard_var = current_thread;  // The first time we grab the guard, it's as -1
  }

  // If there are any halted native threads, signal one and put us on the queue,
  // so that we will be picked up by it.
  if (!halted_native_threads.empty()) {
    pthread_t native_thread = halted_native_threads.front();
    halted_native_threads.pop_front();
    wake(native_thread);
    ready_queue.push_back(ctx);
    return;
  }

  // Otherwise, if we can still start more native threads, start one for us.
  if (native_threads.size() < max_native_threads) {
    start_native_thread(ctx);
    return;
  }

  // Otherwise, we're going to have to put this thread on the ready queue.

  // If we haven't started the preemptifier, do so.
  if (!preemptifier_started) {
    preemptifier_started = true;
    set_preemption_callback(&yield);
    start_preemptifier(native_threads);
  }

  ready_queue.push_back(ctx);
}
