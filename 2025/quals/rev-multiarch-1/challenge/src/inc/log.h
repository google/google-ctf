/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdio.h>
#include <errno.h>

#ifdef DEBUG
#define DLOG(fmt, ...) fprintf(stderr, "[D] " fmt "\n", ##__VA_ARGS__)
#else
#define DLOG(fmt, ...) do {} while(0);
#endif // DEBUG

// log messages relevant to the chal
#define DLOG_KEEP(fmt, ...) fprintf(stderr, "[D] " fmt "\n", ##__VA_ARGS__)

#define ILOG(fmt, ...) fprintf(stderr, "[I] " fmt "\n", ##__VA_ARGS__)
#define WLOG(fmt, ...) fprintf(stderr, "[W] " fmt "\n", ##__VA_ARGS__)
#define ELOG(fmt, ...) fprintf(stderr, "[E] " fmt "\n", ##__VA_ARGS__)
#define ELOGERRNO(fmt, ...) fprintf(stderr, "[E] " fmt " - %s\n", ##__VA_ARGS__, strerror(errno));