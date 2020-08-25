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
#include "semaphore.h"

#include <iostream>

#include "shared.h"

semaphore::semaphore(size_t val) : val_(val) {}

void semaphore::up() {
  enter_critical_section();

  ++val_;

  if (!wait_queue_.empty()) {
    ready_thread(wait_queue_.front());
    wait_queue_.pop_front();
  }

  leave_critical_section();
}

void semaphore::down() {
  enter_critical_section();

  while (val_ == 0) {
    block_thread(&wait_queue_);
  }

  --val_;

  leave_critical_section();
}

semaphore::semaphore(const semaphore& sem) {
  enter_critical_section();
  val_ = sem.val_;
  leave_critical_section();
}
semaphore::semaphore(semaphore&& sem) {
  enter_critical_section();
  val_ = sem.val_;
  leave_critical_section();
}
