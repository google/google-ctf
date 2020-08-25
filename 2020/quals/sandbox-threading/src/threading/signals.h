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
#ifndef EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_KERNEL_H_
#define EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_KERNEL_H_

#include <pthread.h>
#include <vector>

// Halt the currently-running thread.
void halt();

// Wake the target thread if halted. If not halted, queues a wakeup such that
// the next halt() call by that thread will have no effect.
void wake(pthread_t thread);

// Prevent the current thread from being preempted. Any signals will be
// queued.
void disable_preemption();

// Allow the current thread to be preempted. Any signals queued during
// the critical section will be immediately delivered.
void enable_preemption();

// Assert that preemption is disabled for the current thread.
void assert_preemption_disabled();

// Assert that preemption is enabled for the current thread.
void assert_preemption_enabled();

// Whether preemption is currently enabled.
bool preemption_enabled();

// Set the function to be called on preemption.
void set_preemption_callback(void(*callback)());

// Start the thread used for issuing preemptions to other threads.
// Pass in a list of threads to be eligible for preemption.
void start_preemptifier(std::vector<pthread_t> eligible_threads);


#endif  // EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_KERNEL_H_
