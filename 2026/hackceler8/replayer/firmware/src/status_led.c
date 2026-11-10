#include "status_led.h"

#include <zephyr/drivers/led.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(status_led, CONFIG_LOG_DEFAULT_LEVEL);

static const uint8_t LED_INTENSITY = 32;

static const uint32_t TEMP_BLINK_COUNT = 3;

/* Black = LED off. */
static const uint8_t COLOR_BLACK[] = {0, 0, 0};
static const uint8_t COLOR_RED[] = {LED_INTENSITY, 0, 0};
static const uint8_t COLOR_GREEN[] = {0, LED_INTENSITY, 0};
static const uint8_t COLOR_BLUE[] = {0, 0, LED_INTENSITY};
static const k_timeout_t LED_BLINK_DELAY = K_MSEC(200);

const uint8_t *state_to_color(enum led_state state)
{
        switch (state) {
        case LED_STATE_OFF:
                return COLOR_BLACK;

        case LED_STATE_GREEN_FIXED:
                /* Fallthrough */
        case LED_STATE_GREEN_BLINKING:
                return COLOR_GREEN;

        case LED_STATE_BLUE_FIXED:
                return COLOR_BLUE;

        case LED_STATE_RED_FIXED:
                return COLOR_RED;

        default:
                /* Should never happen, turn the LED off. */
                return COLOR_BLACK;
        }
}

static const uint8_t *tmp_blink_to_color(enum led_tmp_blink blink)
{
        switch(blink) {
        case LED_TMP_BLINK_GREEN:
                return COLOR_GREEN;

        case LED_TMP_BLINK_RED:
                return COLOR_RED;

        default:
                return COLOR_BLACK;
        }
}

void led_thread_fn(const struct device *led, struct k_msgq *cmd_queue, void *a3)
{
        ARG_UNUSED(a3);

        // enum led_state led_state = LED_STATE_OFF;
        const uint8_t *current_color = COLOR_BLACK;
        bool blinking = false;
        uint32_t tmp_blink_count = 0;
        struct status_led_cmd cmd;

        if (!device_is_ready(led)) {
                LOG_ERR_DEVICE_NOT_READY(led);
                return;
        }

        for (;;) {
                led_set_color(led, 0, ARRAY_SIZE(COLOR_BLACK), current_color);
                k_timeout_t timeout = blinking ? LED_BLINK_DELAY : K_FOREVER;
                int ret = k_msgq_get(cmd_queue, &cmd, timeout);

                if (ret == -EAGAIN) {
                        __ASSERT(blinking, "Got timeout with non-blinking state");
                        /* Nothing changed and the timeout expired, blink the LED. */

                        if (cmd.blink != LED_TMP_BLINK_NONE) {
                                /* Temporary blinking */
                                if (tmp_blink_count > TEMP_BLINK_COUNT) {
                                        /* Stop the temp blinking. */
                                        cmd.blink = LED_TMP_BLINK_NONE;
                                        current_color = state_to_color(cmd.state);
                                        blinking = cmd.state >= LED_STATE_MIN_BLINKING;
                                } else {
                                        tmp_blink_count++;
                                        if (current_color != COLOR_BLACK) {
                                                current_color = COLOR_BLACK;
                                        } else {
                                                current_color = tmp_blink_to_color(cmd.blink);
                                        }
                                }
                        } else {
                                /* Permanent blinking */
                                if (current_color != COLOR_BLACK) {
                                        current_color = COLOR_BLACK;
                                } else {
                                        current_color = state_to_color(cmd.state);
                                }
                        }
                } else if (ret < 0) {
                        LOG_WRN("LED command queue read failed");
                        continue;
                } else {
                        /* We got a new command. */
                        if (cmd.blink != LED_TMP_BLINK_NONE) {
                                blinking = true;
                                tmp_blink_count = 0;
                                current_color = tmp_blink_to_color(cmd.blink);
                        } else {
                                blinking = cmd.state >= LED_STATE_MIN_BLINKING;
                                current_color = state_to_color(cmd.state);
                        }
                }
        }
}
