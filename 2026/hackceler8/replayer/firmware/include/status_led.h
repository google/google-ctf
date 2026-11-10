#pragma once

#include <stdint.h>

#include <zephyr/kernel.h>

enum led_state {
        LED_STATE_OFF = 0,
        LED_STATE_GREEN_FIXED,
        LED_STATE_BLUE_FIXED,
        LED_STATE_RED_FIXED,

        LED_STATE_GREEN_BLINKING,

        LED_STATE_MIN_BLINKING = LED_STATE_GREEN_BLINKING,
};

enum led_tmp_blink {
        LED_TMP_BLINK_NONE = 0,
        LED_TMP_BLINK_GREEN,
        LED_TMP_BLINK_RED,
};

struct status_led_cmd {
    enum led_state state;
    enum led_tmp_blink blink;
};

extern const uint8_t *state_to_color(enum led_state state);
extern void led_thread_fn(const struct device *led, struct k_msgq *cmd_queue, void *a3);
