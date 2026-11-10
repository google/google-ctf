#pragma once

#include <stdbool.h>
#include <stdint.h>

enum {
    REPLAY_TRACE_FLAGS_WAIT_FOR_RESET = (1 << 0),

    /* Every flag defined above, to validate the flags of an untrusted trace. */
    REPLAY_TRACE_FLAGS_ALL = REPLAY_TRACE_FLAGS_WAIT_FOR_RESET,
};

union buttons {
        struct {
                uint8_t b : 1;
                uint8_t c : 1;
                uint8_t down : 1;
                uint8_t left : 1;
                uint8_t right : 1;
                uint8_t up : 1;
                uint8_t a : 1;
                uint8_t start : 1;
        };
        uint8_t val;
};

/*
 * The number of the last frame an input can be played on. Frame numbers are
 * stored in 24 bits, which is a bit more than 93 hours of play at 50 Hz (and
 * 77 at 60 Hz), far longer than any replay we care about.
 */
#define REPLAY_MAX_FRAME_NUMBER 0xFFFFFFU

/*
 * A single change of the controller state, packed into one word: the number of
 * the frame it happens on in the top 24 bits, the state of the controller the
 * replayer drives in the bottom 8.
 *
 * The replayer keeps every input of a file in RAM at once, so this halves the
 * memory a file costs compared to spelling the two fields out. It also keeps
 * every input naturally aligned, so reading one back is a single load.
 */
struct replay_input {
    union buttons buttons;
    uint32_t frame_number : 24;
};

struct replay_trace {
    uint8_t flags;
    uint16_t num_inputs;
    const struct replay_input *inputs;
};

struct replay_stage {
    struct replay_trace traces[3];
};

struct replay_file {
    uint8_t num_stages;
    const struct replay_stage *stages;
};

static inline bool trace_waits_for_reset(const struct replay_trace *t)
{
    return (t->flags & REPLAY_TRACE_FLAGS_WAIT_FOR_RESET) != 0;
}

static inline bool trace_is_empty(const struct replay_trace *t)
{
    return t->num_inputs == 0;
}

static inline bool trace_is_nop(const struct replay_trace *t)
{
    return trace_is_empty(t) && !trace_waits_for_reset(t);
}
