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
#ifndef EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SEMAPHORE_H_
#define EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SEMAPHORE_H_

#include "shared.h"

struct semaphore {
  semaphore(size_t val);
  void up();
  void down();
  semaphore(const semaphore& sem);
  semaphore(semaphore&& sem);
  
 private:
  size_t val_;
  std::deque<ucontext_t*> wait_queue_;
};

#endif  // EXPERIMENTAL_USERS_IPUDNEY_USERLAND_THREADS_SEMAPHORE_H_
