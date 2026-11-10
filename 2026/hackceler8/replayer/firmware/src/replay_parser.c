/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Parser for the replay files the user uploads over USB. See replay_parser.h
 * for the format.
 *
 * The file is read straight off the FAT volume through a one sector window so
 * that the firmware never needs a buffer as big as the file: the only thing
 * which grows with the size of a replay is the pool of parsed inputs, which is
 * half the size of the file it came from.
 *
 * The input is completely untrusted: it is whatever the user dropped onto the
 * drive. Every read goes through the cursor helpers below, which refuse to
 * read past the end of the file, and every count in the file is checked
 * against both the bytes which are actually there and the room left in the
 * output pools before it is used.
 *
 * Parsing is done in two passes so that a bad file cannot disturb a replay
 * which is already going on: the first pass only reads and decides whether the
 * file is acceptable, the second one fills in the pools. Each pass re-reads
 * and re-checks everything and neither trusts what the other one found: the
 * host owns the sectors the file lives in and is free to rewrite them in
 * between.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/fs/fs.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/toolchain.h>

#include "replay_parser.h"
#include "trace.h"

LOG_MODULE_REGISTER(replay_parser, CONFIG_LOG_DEFAULT_LEVEL);

/* Size of one frame on the drive: u32 frame number plus u32 for the buttons. */
#define FILE_FRAME_SIZE (sizeof(uint32_t) + sizeof(uint32_t))

/* How much of the file is held in memory while it is being parsed. */
#define WINDOW_SIZE 512U

#define TRACES_PER_STAGE (sizeof(((struct replay_stage *)0)->traces) / sizeof(struct replay_trace))

/* An input has to hold a frame number and the state of one player, and no more. */
BUILD_ASSERT(sizeof(struct replay_input) == sizeof(uint32_t), "struct replay_input is not packed");
BUILD_ASSERT(((REPLAY_MAX_FRAME_NUMBER << 8) | UINT8_MAX) == UINT32_MAX,
	     "the frame number and the buttons do not fill an input");

/* The number of stages and inputs has to be representable in the structs. */
BUILD_ASSERT(CONFIG_REPLAY_MAX_STAGES <= UINT8_MAX, "too many stages for struct replay_file");
BUILD_ASSERT(CONFIG_REPLAY_MAX_INPUTS <= UINT16_MAX, "too many inputs for struct replay_trace");

static struct replay_input input_pool[CONFIG_REPLAY_MAX_INPUTS];
static struct replay_stage stage_pool[CONFIG_REPLAY_MAX_STAGES];

struct parser {
	/* The file being parsed. pos is never allowed to go past size. */
	struct fs_file_t *fp;
	size_t size;
	size_t pos;

	/* The bytes of the file in [win_pos, win_pos + win_len). */
	uint8_t window[WINDOW_SIZE];
	size_t win_pos;
	size_t win_len;

	/* Inputs handed out to the traces parsed so far. */
	size_t used_inputs;

	/* Whether to write anything to the pools. */
	bool commit;
};

static inline size_t remaining(const struct parser *p)
{
	/* read_bytes() maintains pos <= size, so this cannot underflow. */
	return p->size - p->pos;
}

/* Refills the window with the bytes of the file starting at pos. */
static bool fill_window(struct parser *p)
{
	ssize_t ret;

	/*
	 * The file is read strictly in order, so it is usually already
	 * positioned where we want it: seeking is only needed when a value
	 * straddled the end of the previous window and left bytes behind.
	 */
	if (p->win_pos + p->win_len != p->pos) {
		if (fs_seek(p->fp, (off_t)p->pos, FS_SEEK_SET) < 0) {
			return false;
		}
	}

	ret = fs_read(p->fp, p->window, MIN(sizeof(p->window), remaining(p)));
	if (ret <= 0) {
		return false;
	}

	p->win_pos = p->pos;
	p->win_len = (size_t)ret;

	return true;
}

static bool read_bytes(struct parser *p, uint8_t *out, size_t len)
{
	size_t done = 0;

	if (remaining(p) < len) {
		return false;
	}

	while (done < len) {
		size_t offset;
		size_t chunk;

		if (p->pos < p->win_pos || p->pos >= p->win_pos + p->win_len) {
			if (!fill_window(p)) {
				return false;
			}
		}

		offset = p->pos - p->win_pos;
		chunk = MIN(len - done, p->win_len - offset);

		memcpy(&out[done], &p->window[offset], chunk);

		done += chunk;
		p->pos += chunk;
	}

	return true;
}

static bool read_u8(struct parser *p, uint8_t *out)
{
	return read_bytes(p, out, sizeof(*out));
}

static bool read_u32(struct parser *p, uint32_t *out)
{
	uint8_t raw[sizeof(uint32_t)];

	if (!read_bytes(p, raw, sizeof(raw))) {
		return false;
	}

	*out = sys_get_le32(raw);

	return true;
}

static int parse_frames(struct parser *p, uint32_t num_frames, struct replay_trace *trace,
			unsigned int stage, unsigned int slot)
{
	struct replay_input *inputs = &input_pool[p->used_inputs];
	uint32_t previous_frame = 0;

	/*
	 * Check that the frames are all there before reading any of them. The
	 * division avoids overflowing when num_frames is huge.
	 */
	if (num_frames > remaining(p) / FILE_FRAME_SIZE) {
		LOG_ERR("stage %u slot %u claims %u frames but only %zu bytes are left", stage,
			slot, num_frames, remaining(p));
		return -EINVAL;
	}

	/* Check that they fit in what is left of the pool. */
	if (num_frames > ARRAY_SIZE(input_pool) - p->used_inputs) {
		LOG_ERR("stage %u slot %u does not fit, at most %zu inputs are supported", stage,
			slot, ARRAY_SIZE(input_pool));
		return -ENOSPC;
	}

	for (uint32_t i = 0; i < num_frames; i++) {
		uint32_t frame_number;
		uint32_t players;

		if (!read_u32(p, &frame_number) || !read_u32(p, &players)) {
			/* The bytes were counted above, so the read itself failed. */
			LOG_ERR("failed to read frame %u of stage %u slot %u", i, stage, slot);
			return -EIO;
		}

		/*
		 * The recording holds one entry per change of the controller
		 * state, so the frame numbers only ever move forward.
		 */
		if (i > 0 && frame_number < previous_frame) {
			LOG_ERR("frame %u of stage %u slot %u goes back in time (%u after %u)", i,
				stage, slot, frame_number, previous_frame);
			return -EINVAL;
		}
		previous_frame = frame_number;

		/* An input only has room for a 24 bit frame number. */
		if (frame_number > REPLAY_MAX_FRAME_NUMBER) {
			LOG_ERR("frame %u of stage %u slot %u is too far away (%u, max %u)", i,
				stage, slot, frame_number, REPLAY_MAX_FRAME_NUMBER);
			return -EINVAL;
		}

		/*
		 * The frame holds one byte of buttons per player, player 1
		 * first. The replayer only drives player 1, so rather than
		 * quietly playing a file as something other than what it says
		 * we refuse files which ask for the other players.
		 */
		if ((players & ~0xFFU) != 0) {
			LOG_ERR("frame %u of stage %u slot %u drives more than one player (0x%08x)",
				i, stage, slot, players);
			return -ENOTSUP;
		}

		if (p->commit) {
			inputs[i] = (struct replay_input){
			        .buttons.val = (uint8_t)players,
				.frame_number = frame_number,
			};
		}
	}

	if (p->commit) {
		trace->num_inputs = (uint16_t)num_frames;
		trace->inputs = num_frames > 0 ? inputs : NULL;
	}

	p->used_inputs += num_frames;

	return 0;
}

static int parse_trace(struct parser *p, struct replay_trace *trace, unsigned int stage,
		       unsigned int slot)
{
	uint32_t num_frames;
	uint8_t flags;

	if (!read_u8(p, &flags)) {
		LOG_ERR("truncated header of stage %u slot %u", stage, slot);
		return -EINVAL;
	}

	/*
	 * The byte in the file holds the REPLAY_TRACE_FLAGS_* bitmask as is,
	 * so anything outside of the flags we know about is a bad file.
	 */
	if ((flags & ~REPLAY_TRACE_FLAGS_ALL) != 0) {
		LOG_ERR("stage %u slot %u has unknown flags 0x%02x", stage, slot, flags);
		return -EINVAL;
	}

	if (!read_u32(p, &num_frames)) {
		LOG_ERR("truncated header of stage %u slot %u", stage, slot);
		return -EINVAL;
	}

	if (num_frames > UINT16_MAX) {
		LOG_ERR("stage %u slot %u has too many frames (%u)", stage, slot, num_frames);
		return -EINVAL;
	}

	if (p->commit) {
		trace->flags = flags;
	}

	return parse_frames(p, num_frames, trace, stage, slot);
}

/*
 * The parser is static rather than a local: it carries the window, and the
 * storage thread does not have half a kilobyte of stack to spare for it. Both
 * passes run on that thread, one after the other.
 */
static struct parser parser;

static int parse(struct fs_file_t *fp, size_t size, struct replay_file *out, bool commit)
{
	struct parser *p = &parser;
	uint8_t num_stages;
	int ret;

	if (fp == NULL) {
		return -EINVAL;
	}

	ret = fs_seek(fp, 0, FS_SEEK_SET);
	if (ret < 0) {
		LOG_ERR("failed to rewind the file: %d", ret);
		return ret;
	}

	/* A pass starts over from the beginning of the file, window included. */
	*p = (struct parser){
		.fp = fp,
		.size = size,
		.commit = commit,
	};

	if (!read_u8(p, &num_stages)) {
		LOG_ERR("the file is empty");
		return -EINVAL;
	}

	if (num_stages == 0) {
		LOG_ERR("the file has no stages");
		return -EINVAL;
	}

	if (num_stages > ARRAY_SIZE(stage_pool)) {
		LOG_ERR("the file has %u stages, at most %zu are supported", num_stages,
			ARRAY_SIZE(stage_pool));
		return -ENOSPC;
	}

	for (unsigned int stage = 0; stage < num_stages; stage++) {
		for (unsigned int slot = 0; slot < TRACES_PER_STAGE; slot++) {
			ret = parse_trace(p, &stage_pool[stage].traces[slot], stage, slot);
			if (ret < 0) {
				return ret;
			}
		}
	}

	if (p->pos != size) {
		LOG_ERR("%zu bytes of trailing data after the last stage", size - p->pos);
		return -EINVAL;
	}

	if (commit) {
		out->num_stages = num_stages;
		out->stages = stage_pool;

		LOG_INF("parsed %u stages and %zu inputs", num_stages, p->used_inputs);
	}

	return 0;
}

int replay_parser_check(struct fs_file_t *fp, size_t size)
{
	return parse(fp, size, NULL, false);
}

int replay_parser_build(struct fs_file_t *fp, size_t size, struct replay_file *out)
{
	if (out == NULL) {
		return -EINVAL;
	}

	return parse(fp, size, out, true);
}
