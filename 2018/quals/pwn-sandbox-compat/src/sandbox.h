/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _SANDBOX_H
#define _SANDBOX_H

#define LAST_PAGE       (void *)((1L << 32) - PAGE_SIZE)
#define KERNEL_PAGE     (void *)(1L << 32)
#define USER_CODE       (void *)0xdead0000
#define USER_STACK      (void *)0xbeef0000
#define STACK_SIZE      (16 * PAGE_SIZE)

extern int kernel(unsigned int argv0, unsigned int argv1, unsigned int argv2,
                  unsigned int argv3);

#endif
