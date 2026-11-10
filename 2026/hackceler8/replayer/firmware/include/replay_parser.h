/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <zephyr/fs/fs.h>

#include "trace.h"

/*
 * Parser for the replay files built by plugins/builder.py.
 *
 * Every field is little endian and nothing is padded or aligned:
 *
 *   file:  u8  num_stages
 *          stage[num_stages]
 *
 *   stage: trace  (played when button 0 is pressed)
 *          trace  (played when button 1 is pressed)
 *          trace  (played when button 2 is pressed)
 *
 *   trace: u8  flags        a REPLAY_TRACE_FLAGS_* bitmask
 *          u32 num_frames
 *          frame[num_frames]
 *
 *   frame: u32 frame_number
 *          u8  controller_state[4]  (one byte per player)
 *
 * The file is read through the fs API rather than from a buffer, so the
 * firmware only ever holds one sector of it at a time. A frame becomes a
 * struct replay_input, which is half its size: frame numbers above
 * REPLAY_MAX_FRAME_NUMBER do not fit and are rejected, and so are frames which
 * drive any player but the first, since the replayer only has one controller
 * to drive.
 *
 * The parsed file refers to inputs held in a statically allocated pool, whose
 * size is capped by CONFIG_REPLAY_MAX_INPUTS and CONFIG_REPLAY_MAX_STAGES.
 */

/*
 * Checks that the file holds a well formed replay which fits in the pool,
 * without touching any state. The file has to be open for reading and size has
 * to be its size; both passes rewind it themselves. Returns 0 if the file can
 * be parsed, a negative errno otherwise.
 */
int replay_parser_check(struct fs_file_t *fp, size_t size);

/*
 * Parses the file into *out. Every check replay_parser_check() does is
 * repeated, so this is just as safe to call on untrusted data, it only returns
 * 0 for a file which is completely valid.
 *
 * This overwrites the pool the inputs live in, which means that any
 * replay_file filled in by a previous call (and every trace and input reachable
 * from it) is invalidated, whether this call succeeds or not. The caller has to
 * make sure nothing is using the old file anymore.
 */
int replay_parser_build(struct fs_file_t *fp, size_t size, struct replay_file *out);

