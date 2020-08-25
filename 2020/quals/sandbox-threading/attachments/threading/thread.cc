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
#include "thread.h"
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

#include "shared.h"
#include "signals.h"
#include "semaphore.h"


struct thread_control_block {
  std::function<void()> callable;
  void* stack = nullptr;

  std::atomic<bool> thread_dead = false;
  semaphore crit_sem = 1;
  std::deque<ucontext_t*> join_q;
};

namespace {

void thread_func(std::shared_ptr<thread_control_block>* tcb_ptr) {
  assert_guard_held();
  cleanup_after_switch();

  leave_critical_section();
  (*tcb_ptr)->callable();
  enter_critical_section();

  // Allow joined threads to proceed.
  (*tcb_ptr)->thread_dead = true;
  while ((*tcb_ptr)->join_q.size() > 1) {
    ready_thread((*tcb_ptr)->join_q.front());
    (*tcb_ptr)->join_q.pop_front();
  }
  // For the last joined thread, just move it to the ready queue directly
  // rather than using ready_thread. This means it will be switched to by
  // end_thread() rather than possibly incurring the overhead of starting or
  // awakening a native thread.
  if (!(*tcb_ptr)->join_q.empty()) {
    ready_queue.push_back((*tcb_ptr)->join_q.front());
    (*tcb_ptr)->join_q.pop_front();
  }

  if (!(*tcb_ptr)->join_q.empty()) {
    std::cerr << "Non-empty join queue at end of join" << std::endl;
    _exit(1);
  }

  add_pending_cleanup([tcb_ptr]() {
    delete tcb_ptr;
  });
  end_thread((*tcb_ptr)->stack);
}

}  // namespace

void yield() {
  enter_critical_section();

  if (!ready_queue.empty()) {
    block_thread(&ready_queue);
  }

  leave_critical_section();
}

uthread::uthread(std::function<void()> callable) {
  enter_critical_section();

  tcb_ = std::make_shared<thread_control_block>();
  auto* tcb_ptr = new std::shared_ptr<thread_control_block>(tcb_);
  tcb_->callable = std::move(callable);

  ucontext_t* ctx = new ucontext_t();
  getcontext(ctx);
  ctx->uc_stack.ss_sp = alloc_stack();
  ctx->uc_stack.ss_size = stack_size;
  tcb_->stack = ctx->uc_stack.ss_sp;
  makecontext(ctx, reinterpret_cast<void (*)()>(&thread_func), 1, tcb_ptr);

  ready_thread(ctx);

  leave_critical_section();
}

void uthread::join() {
  if (!tcb_) return;

  // Throw in some double-checked locking for funzies. Uses atomics, so it's
  // actually not undefined behavior.
  if (tcb_->thread_dead) return;

  enter_critical_section();
  while (!tcb_->thread_dead) {
    block_thread(&tcb_->join_q);
  }
  leave_critical_section();
}

void set_max_native_threads(int threads) {
  set_max_native_threads_impl(threads);
}

void uthread_safe_sleep(uint64_t microseconds) {
  auto target = std::chrono::system_clock::now() + std::chrono::microseconds(microseconds);
  yield();

  while(true) {
    auto difference = target - std::chrono::system_clock::now();
    if (difference > std::chrono::microseconds(0)) {
      std::this_thread::sleep_for(difference);
    } else {
      break;
    }
  }
}

// Code here
