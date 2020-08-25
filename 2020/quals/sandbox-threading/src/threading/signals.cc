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
#include "signals.h"
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>

#include <unistd.h>
#include <csignal>
#include <iostream>
#include <random>
#include <thread>
#include <array>

namespace {

bool preemption_disabled() {
  sigset_t sigs;
  if(pthread_sigmask(SIG_SETMASK, nullptr, &sigs)) {
    std::cerr << "Failed to get sigs for preemption_disabled(): " << strerror(errno) << std::endl;
    _exit(1);
  }
  return sigismember(&sigs, SIGUSR1);
}

void halt_sighandler (int, siginfo_t *, void *) {

}

void(*preemption_callback)() = nullptr;

// Set to true when we're in a preemption cascade, to discard any recursive
// signals.
volatile thread_local bool preemption_cascade = false;

void call_preemption_cb(int, siginfo_t *, void *) {
  if (preemption_cascade) {
    return;
  }

  // Discard any extra preemptions.
  // Even though this signal handler is NODEFER, Linux still blocks the
  // signals while in this handler if it's called immediately upon unblocking
  // pending signals. We don't want that.
  preemption_cascade = true;
  while(preemption_disabled()) {
    enable_preemption();
  }
  preemption_cascade = false;

  assert_preemption_enabled();
  preemption_callback();
}

// Set up the main mask at program start to ensure wakes are correctly queued.
// Set up the signal handler for wake (to do nothing).
// Set up the signal handler for preemption (to call the user-provided cb).
// Start a background thread to repeatedly send preemptions.
sigset_t halt_sigset = []() {
  sigset_t sigusr_set;
  sigemptyset(&sigusr_set);
  sigaddset(&sigusr_set, SIGUSR1);
  sigset_t old_set;
  if (pthread_sigmask(SIG_UNBLOCK, &sigusr_set, &old_set)) {
  std::cerr << "Failed to unblock sigusr1 for halt_sigset(): " << strerror(errno) << std::endl;
  _exit(1);
  }

  sigemptyset(&sigusr_set);
  sigaddset(&sigusr_set, SIGUSR2);
  if (pthread_sigmask(SIG_BLOCK, &sigusr_set, &old_set)) {
    std::cerr << "Failed to block sigusr2 for halt_sigset(): " << strerror(errno) << std::endl;
    _exit(1);
  }

  struct sigaction new_action, old_action;
  memset(&new_action, 0, sizeof(new_action));
  memset(&old_action, 0, sizeof(old_action));
  new_action.sa_sigaction = &halt_sighandler;
  new_action.sa_flags = SA_SIGINFO;
  if(sigaction(SIGUSR2, &new_action, &old_action)) {
    std::cerr << "Failed to set sigusr2 handler" << strerror(errno) << std::endl;
    _exit(1);
  }

  struct sigaction new_action2;
  memset(&new_action2, 0, sizeof(new_action2));
  new_action2.sa_sigaction = &call_preemption_cb;
  new_action2.sa_flags = SA_NODEFER | SA_SIGINFO;
  if(sigaction(SIGUSR1, &new_action2, &old_action)) {
    std::cerr << "Failed to set sigusr1 handler" << strerror(errno) << std::endl;
    _exit(1);
  }

  sigaddset(&old_set, SIGUSR1);

  assert_preemption_enabled();

  return old_set;
}();

}  // namespace

// Halt the currently-running thread.
void halt() {
  assert_preemption_disabled();
  sigsuspend(&halt_sigset);
  assert_preemption_disabled();
}

// Wake the target thread if halted.
void wake(pthread_t thread) {
  if(pthread_kill(thread, SIGUSR2)) {
    std::cerr << "Failed to wake " << thread << ": " << strerror(errno) << std::endl;
    _exit(1);
  }
}

// Prevent the current thread from being interrupted. Any signals will be
// queued.
void disable_preemption() {
  sigset_t sigusr_set;
  sigemptyset(&sigusr_set);
  sigaddset(&sigusr_set, SIGUSR1);
  sigset_t old_set;
  if (pthread_sigmask(SIG_BLOCK, &sigusr_set, &old_set)) {
    std::cerr << "Failed to disable preemption: " << strerror(errno) << std::endl;
    _exit(1);
  }
}

// Allow the current thread to be interrupted. Any signals queued during
// the critical section will be immediately delivered.
void enable_preemption() {
  sigset_t sigusr_set;
  sigemptyset(&sigusr_set);
  sigaddset(&sigusr_set, SIGUSR1);
  sigset_t old_set;
  if (pthread_sigmask(SIG_UNBLOCK, &sigusr_set, &old_set)) {
    std::cerr << "Failed to enable preemption: " << strerror(errno) << std::endl;
    _exit(1);
  }
}

// Assert that preemption is disabled for the current thread.
void assert_preemption_disabled() {
  sigset_t sigs;
  if (pthread_sigmask(SIG_SETMASK, nullptr, &sigs)) {
    std::cerr << "Failed to get mask in assert_preemption_disabled: " << strerror(errno) << std::endl;
    _exit(1);
  }
  if (!sigismember(&sigs, SIGUSR1)) {
    std::cerr << "Thread thinks preemption is disabled, but it's enabled." << std::endl;
    _exit(1);
  }
}

// Assert that preemption is enabled for the current thread.
void assert_preemption_enabled() {
  sigset_t sigs;
  if (pthread_sigmask(SIG_SETMASK, nullptr, &sigs)) {
    std::cerr << "Failed to get mask in assert_preemption_enabled: " << strerror(errno) << std::endl;
    _exit(1);
  }
  if (sigismember(&sigs, SIGUSR1)) {
    std::cerr << "Thread thinks preemption is enabled, but it's disabled." << std::endl;
    _exit(1);
  }
}

void set_preemption_callback(void(*callback)()) {
  preemption_callback = callback;
}

constexpr int max_preemption_micros = 30000;
void start_preemptifier(std::vector<pthread_t> eligible_threads) {
  std::thread preemptifier([eligible_threads]() {
    pthread_setname_np(pthread_self(), "preemptifier");
    std::random_device rd;
    std::uniform_int_distribution<int> generator(0, max_preemption_micros);
    while (true) {
      for (int i = 0; i < eligible_threads.size(); ++i) {
        usleep(generator(rd) / eligible_threads.size());
        if (pthread_kill(eligible_threads[i], SIGUSR1)) {
          std::cerr << "Failed to preempt thread " << i << " " << eligible_threads[i] << ": " << strerror(errno) << std::endl;
        }
      }
    }
  });
  preemptifier.detach();
}
