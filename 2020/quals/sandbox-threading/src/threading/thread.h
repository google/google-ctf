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
#ifndef EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_THREAD_H_
#define EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_THREAD_H_

#include <functional>
#include <memory>

// Cause the current thread to yield its native thread and be moved to the back
// of the ready queue.
void yield();

// Sets the maximum number of native threads to use. Until this number is
// reached, new threads will be backed by a native thread. Once this number
// is reached, native threads will start to be shared. May not be called after
// threads have been created.
void set_max_native_threads(int threads);

// Sleep for the specified number of microseconds in a thread safe way. Does
// not yield the underlying native thread.
void uthread_safe_sleep(uint64_t microseconds);

struct thread_control_block;

class uthread {
 public:
  uthread() = default;
  uthread(std::function<void()> callable);
  void join();

  uthread(const uthread& other) = default;
  uthread(uthread&& other) = default;
  uthread& operator=(const uthread& other) = default;

  std::shared_ptr<thread_control_block> tcb_;
};

#endif  // EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_THREAD_H_
