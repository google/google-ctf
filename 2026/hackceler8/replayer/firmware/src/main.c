#include <stdalign.h>

#include <hardware/structs/otp.h>
#include <hardware/regs/otp.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/input/input.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/spinlock.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/task_wdt/task_wdt.h>

#include "drivers/replayer/megadrive.h"
#include "replay_parser.h"
#include "status_led.h"
#include "trace.h"
#include "trace_storage.h"
#include "usb.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

static const struct device *const replayer_dev = DEVICE_DT_GET(DT_NODELABEL(replayer_port1));
static const k_timeout_t drain_poll_interval = K_MSEC(10);
static const k_timeout_t reset_timeout = K_MSEC(100);

static const struct gpio_dt_spec replay_en_gpio = GPIO_DT_SPEC_GET(DT_PATH(zephyr_user), replay_en_gpios);
static const struct gpio_dt_spec port1_select_gpio = GPIO_DT_SPEC_GET(DT_PATH(replayer_port1), select_gpios);

enum REPLAYER_STATE {
	/*
	 * The replayer is waiting for the user to select the next trace.
	 * Controllers are enabled. active_trace is NULL and the trace queue
	 * is empty. The status LED is blue when the player can still
         * enqueue traces, and red when they've reached the end of the current
         * file.
	 */
	REPLAYER_STATE_IDLE,

	/*
	 * The replayer is waiting for the the console to reset.
	 * Controllers are enabled. active_trace is not NULL and the active
	 * trace has the reset flag enabled. The status LED is green and
	 * blinking.
	 */
	REPLAYER_STATE_WAITING_FOR_RESET,

	/*
	 * The replayer is playing a trace and there are still inputs to play in
	 * the active trace. Either active_trace is non-NULL or there are traces
	 * in the queue. The status LED is fixed green.
	 * Controllers are disabled.
	 */
	REPLAYER_STATE_PLAYING,

	/*
	 * The replayer is waiting for the the PIO state machine to finish transmitting
	 * frames which are still queued in the state machine's TX FIFO.
	 * Controllers are disabled. Either active_trace is NULL and the queue
	 * is empty or active_trace is not NULL and the active trace waits for
	 * a reset. The status LED is fixed green.
	 */
	REPLAYER_STATE_DRAINING,
};

/* The traces the player selects are enqueued here and played in FIFO order. */
K_MSGQ_DEFINE_STATIC(trace_queue, sizeof(struct replay_trace *), 256, alignof(struct replay_trace *));

/* The file parsed out of the last upload, referenced by current_file. */
static struct replay_file uploaded_file;

/* state_lock synchronizes access to all the shared variables below. */
static struct k_spinlock state_lock;
/* State machine state, see enum REPLAYER_STATE. */
static enum REPLAYER_STATE current_state = REPLAYER_STATE_IDLE;
/*
 * The active trace is the trace that the replayer is currently playing from,
 * or that will be played after the next console reset.
 */
static const struct replay_trace *active_trace;
/* The index of the first stage where the player still hasn't selected a trace. */
static uint8_t current_stage;
/* The currently-loaded replay file uploaded over USB. */
static const struct replay_file *current_file;
/* The number of frames which have elapsed since the beginning of the active trace. */
static uint32_t current_frame;
/* The index of the first unsent input in the active trace. */
static uint32_t next_input;
/*
 * The current state of the controllers. At the start of a trace all the buttons
 * are not pressed. Later this is the button state from the latest played input.
 */
static union buttons current_controller_state;

/* Replay status LED. */
K_MSGQ_DEFINE_STATIC(replay_led_cmd_queue, sizeof(struct status_led_cmd), 4, alignof(struct status_led_cmd));
K_THREAD_DEFINE(replay_led_thread, CONFIG_STATUS_LED_THREAD_STACK_SIZE, led_thread_fn, DEVICE_DT_GET(DT_NODELABEL(status_led1)), &replay_led_cmd_queue, NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);

static void status_led_set_color(enum led_state state)
{
        k_msgq_put(&replay_led_cmd_queue, &(struct status_led_cmd){.state = state}, K_NO_WAIT);
}

/* Trace status LED */
K_MSGQ_DEFINE_STATIC(trace_led_cmd_queue, sizeof(struct status_led_cmd), 4, alignof(struct status_led_cmd));
K_THREAD_DEFINE(trace_led_thread, CONFIG_STATUS_LED_THREAD_STACK_SIZE, led_thread_fn, DEVICE_DT_GET(DT_NODELABEL(status_led2)), &trace_led_cmd_queue, NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);

static void trace_led_set_color(enum led_state state, enum led_tmp_blink blink)
{
        k_msgq_put(&trace_led_cmd_queue, &(struct status_led_cmd){.state = state, .blink = blink}, K_NO_WAIT);
}

static int32_t pio_new_input_cb(void *user_data);

/*
 * Start playing the active trace. Call only while holding state_lock.
 */
static void replayer_resume_playing_locked(void)
{
	__ASSERT(active_trace != NULL || k_msgq_num_used_get(&trace_queue) > 0,
	        "resumed playing with no playable trace");

	current_state = REPLAYER_STATE_PLAYING;
	/* Switch the state to fixed green. */
	status_led_set_color(LED_STATE_GREEN_FIXED);
	gpio_pin_set_dt(&replay_en_gpio, 1);
	megadrive_pio_start(replayer_dev);
	megadrive_pio_set_input_callback(replayer_dev, pio_new_input_cb, NULL);
}

/*
 * Start waiting for the console to reset. The current trace must wait for
 * a reset. Call only when holding state_lock.
 */
static void replayer_wait_for_reset_locked(void)
{
	__ASSERT(active_trace != NULL && trace_waits_for_reset(active_trace),
	        "waiting for reset when the trace doesn't require it");

	current_state = REPLAYER_STATE_WAITING_FOR_RESET;
	/* Switch the status LED to blinking green. */
	status_led_set_color(LED_STATE_GREEN_BLINKING);
}

/*
 * Only call while holding state_lock. Returns true when there is a trace which
 * is playable right now, false otherwise.
 */
static bool dequeue_trace_locked(void)
{
	/*
	 * We are switching to a new trace (or stopping if there are no traces
	 * left in the queue). In any case reset the per-trace state.
	 */
	current_frame = 0;
	next_input = 0;
	current_controller_state.val = 0;

	do {
		/* Check if there is something in the queue. */
		int ret = k_msgq_get(&trace_queue, &active_trace, K_NO_WAIT);
		if (ret < 0) {
			/* Nothing left in the queue, go idle. */
			active_trace = NULL;
			return false;
		}

		if (trace_waits_for_reset(active_trace)) {
			/* The new trace waits for a reset. Don't play any of its inputs just yet. */
			return false;
		}
		/* Skip empty traces that don't wait for a reset */
	} while (trace_is_empty(active_trace));

	return true;
}

static void replayer_go_idle_locked(void)
{
        current_state = REPLAYER_STATE_IDLE;
        if (current_file == NULL) {
                status_led_set_color(LED_STATE_OFF);
        } else if (current_stage >= current_file->num_stages) {
                /* We've reached the end of the file, show a red LED. */
                status_led_set_color(LED_STATE_RED_FIXED);
        } else {
                /* The player can still enqueue stages, show a blue LED. */
                status_led_set_color(LED_STATE_BLUE_FIXED);
        }
}

/* The console has just come out of reset. Begin playing the next trace. */
static void replayer_start_trace_after_reset_locked(void)
{
	if (!trace_is_empty(active_trace)) {
		/* The active trace is nonempty, start now. */
		replayer_resume_playing_locked();
		return;
	}

	/* The active trace was empty and only waited for a reset. Try to get a new one. */
	if (dequeue_trace_locked()) {
		/* The new active trace is playable immediately, start now. */
		replayer_resume_playing_locked();
		return;
	}

	if (active_trace == NULL) {
		/* The queue is empty, go idle. */
		replayer_go_idle_locked();
		return;
	}

	/*
	 * The only remaining case is that the next trace also waits for a
	 * reset, so go back to waiting.
	 */
	replayer_wait_for_reset_locked();
}

/*
 * Called when the replayer hasn't seen a rising edge on SELECT in over 100ms.
 */
static void reset_handler(struct k_work *work)
{
	k_spinlock_key_t spin_key = k_spin_lock(&state_lock);
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	k_timeout_t reschedule_delay = reset_timeout;

	switch (current_state) {
	case REPLAYER_STATE_WAITING_FOR_RESET:
		/*
		 * The replayer was waiting for a reset, and it happened
		 * (select was high for over 100ms).
		 */
		replayer_start_trace_after_reset_locked();
		reschedule_delay = K_TIMEOUT_SUM(reset_timeout, K_MSEC(50));
		break;

	default:
		/*
		 * This can happen spuriously, don't do anything. For example
		 * it happens when the player enters the pause menu, because
		 * the game stops polling the controllers for a little bit even
		 * though the console didn't reset.
		 */
		break;
	}

	k_work_reschedule(dwork, reschedule_delay);
	k_spin_unlock(&state_lock, spin_key);
}
K_WORK_DELAYABLE_DEFINE(reset_work, reset_handler);

/*
 * Called when the replayer is in the DRAINING state and it's still waiting
 * for the state machine to finish transmitting input enqueued in the TX FIFO.
 */
static void pio_fifo_drain_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	k_spinlock_key_t spin_key = k_spin_lock(&state_lock);

	/*
	 * If the replayer used to be DRAINING and a button press transitioned it back to
	 * playing, it is still possible that the queued work was cancelled after it had already
	 * been scheduled for execution. In this case the state is no longer DRAINING and this
	 * function shouldn't do anything.
	 */
	if(current_state != REPLAYER_STATE_DRAINING) {
		goto out;
	}

	/*
	 * Check if the state machine has fully played all the input we sent to
	 * it.
	 */
	if (!megadrive_pio_is_drained(replayer_dev)) {
		/* It has not yet finished, check again later. */
		k_work_reschedule(dwork, drain_poll_interval);
		goto out;
	}

	/*
	 * We are in the draining state and the state machine has fully finished
	 * playing the input. We either ran out of input completely (in which
	 * case active_trace is NULL) or the next trace wants to wait for a
	 * reset. In any case re-enable the controllers and stop the state
	 * machine.
	 */
	megadrive_pio_stop(replayer_dev);
	gpio_pin_set_dt(&replay_en_gpio, 0);

	if (active_trace == NULL) {
		/* We ran out of input, go to the idle state. */
		replayer_go_idle_locked();
	} else {
		/*
		 * The only other way to get here is to have an active trace
		 * that waits for a reset.
		 */
		__ASSERT(trace_waits_for_reset(active_trace), "TX FIFO drained while active trace doesn't wait for reset");
		replayer_wait_for_reset_locked();
	}

out:
	k_spin_unlock(&state_lock, spin_key);
}
K_WORK_DELAYABLE_DEFINE(pio_fifo_drain_work, pio_fifo_drain_handler);

/* Call only while holding state_lock. */
static void replayer_start_draining_locked(void)
{
	__ASSERT((active_trace == NULL && k_msgq_num_used_get(&trace_queue) == 0) || (active_trace != NULL && trace_waits_for_reset(active_trace)), "invalid state to start draining");

	current_state = REPLAYER_STATE_DRAINING;
	megadrive_pio_set_input_callback(replayer_dev, NULL, NULL);
	k_work_schedule(&pio_fifo_drain_work, drain_poll_interval);
}

/* Called from the TX FIFO not full ISR. */
static int32_t pio_new_input_cb(void *user_data)
{
	/* By default, signal that there is no new input. */
	int32_t ret = -1;
	k_spinlock_key_t spin_key = k_spin_lock(&state_lock);

	__ASSERT(current_state == REPLAYER_STATE_PLAYING, "console input ISR called when not playing");

	/* Try to get a new trace if necessary. */
	if (active_trace == NULL) {
		/*
		 * We just began playing or the active trace was an empty trace
		 * that only waits for reset.
		 * Try to get a new trace. If we should stop (because we need
		 * to wait for a reset or we ran out of traces) then start
		 * draining the FIFO.
		 */
		if (!dequeue_trace_locked()) {
			replayer_start_draining_locked();
			goto out;
		}
	}

	__ASSERT(next_input < active_trace->num_inputs, "trace input OOB");

	uint32_t next_input_frame = active_trace->inputs[next_input].frame_number;
	if (next_input_frame > current_frame) {
		/* Resend the previous input. */
		ret = current_controller_state.val;
	} else {
		/* We've reached the next input, send that and advance. */
		ret = active_trace->inputs[next_input].buttons.val;
		current_controller_state.val = ret;
		next_input++;
	}

	/* Increment the frame number */
	current_frame++;

	if (next_input == active_trace->num_inputs) {
		/* We've reached the end of the active trace, load the next. */
		if (!dequeue_trace_locked()) {
			replayer_start_draining_locked();
		}
	}
out:
	k_spin_unlock(&state_lock, spin_key);
	return ret;
}


/* Called when the user presses a button to enqueue a new stage. */
static void replayer_enqueue_next_stage(uint8_t trace_index)
{
	k_spinlock_key_t spin_key = k_spin_lock(&state_lock);
	/* If no file is loaded then there is nothing to do. */
	if (current_file == NULL) {
		goto out;
	}

	/* If we've reached the end of the file then there is nothing to do. */
	if (current_stage >= current_file->num_stages) {
		goto out;
	}

	const struct replay_trace *selected_trace = &current_file->stages[current_stage].traces[trace_index];
	current_stage++;

	if (trace_is_nop(selected_trace)) {
		/*
		 * If the replayer is idle the replay status LED is blue right
		 * now. If this is the last trace and it's a nop then we never
		 * go to the active state and idle gain, missing the code path
		 * where the status LED normally becomes red. So we do it here
		 * instead. */
		if (current_state == REPLAYER_STATE_IDLE && current_stage == current_file->num_stages) {
			status_led_set_color(LED_STATE_RED_FIXED);
		}
		goto out;
	}

	/* Enqueue the new trace. */
	k_msgq_put(&trace_queue, &selected_trace, K_NO_WAIT);

	switch (current_state) {
	case REPLAYER_STATE_DRAINING:
		/*
		 * We can be in the draining state either because the active
		 * trace is waiting for a reset or because the replayer ran out
		 * of queued traces to play.
		 * If there is an active trace that is waiting for reset we
		 * shouldn't start playing again immediately, but keep draining.
		 */
		if (active_trace == NULL) {
			if (trace_waits_for_reset(selected_trace)) {
				/*
				 * There was no active trace, but the newly-enqueued
				 * trace waits for a reset. In this case we should
				 * dequeue it so that the drain handler knows
				 * that it needs to transition to waiting for a
				 * reset later but otherwise let the draining continue.
				 */
				dequeue_trace_locked();
			} else {
				/*
				 * If there is no active trace and the new trace
				 * does not wait for a reset then play it
				 * immediately.
				 */
				k_work_cancel_delayable(&pio_fifo_drain_work);
				replayer_resume_playing_locked();
			}
		} else {
			__ASSERT(trace_waits_for_reset(active_trace), "draining when the active trace is not waiting for reset");
		}
		break;

	case REPLAYER_STATE_IDLE:
		__ASSERT(active_trace == NULL, "idle but active_trace is not NULL");
		/*
		 * The replayer was idle, so the selected trace will become the
		 * active trace immediately.
		 */
		if (trace_waits_for_reset(selected_trace)) {
			/*
			 * If the new active trace waits for a reset then the
			 * replayer should not start playing right away. In that case
			 * we can already dequeue the trace and go into the waiting
			 * for reset mode without doing a roundtrip through the ISR.
			 */
			dequeue_trace_locked();
			replayer_wait_for_reset_locked();
		} else {
			/* Otherwise, start playing. */
			replayer_resume_playing_locked();
		}
		break;

	default:
		/*
		 * If the replayer is waiting for reset or already playing, then
		 * we don't need to do anything.
		 */
		break;
	}

out:
	k_spin_unlock(&state_lock, spin_key);
}

/*
 * Stops the replay right now and puts the replayer back in the idle state.
 * Call only while holding state_lock.
 */
static void replayer_stop_locked(void)
{
	/* Disable the TX FIFO interrupt. */
	megadrive_pio_set_input_callback(replayer_dev, NULL, NULL);

	/* Stop the state machine without waiting for it to drain. */
	megadrive_pio_stop(replayer_dev);

	/* Re-enable the controllers. */
	gpio_pin_set_dt(&replay_en_gpio, 0);

	/* Clear all enqueued traces. */
	k_msgq_purge(&trace_queue);

	/* Clear the active trace. */
	active_trace = NULL;

	/* Reset the current stage to the first. */
	current_stage = 0;

	/* Reset the state to idle. */
	replayer_go_idle_locked();

	current_frame = 0;
	next_input = 0;
	current_controller_state.val = 0;

	/* Cancel any pending drain work */
	k_work_cancel_delayable(&pio_fifo_drain_work);
}

/*
 * Stop replaying immediately, flush the trace queue and rewind to the beginning
 * of the file.
 */
static void replayer_immediate_stop(void)
{
	k_spinlock_key_t spin_key = k_spin_lock(&state_lock);

	/* If no file is loaded then there is nothing to do. */
	if (current_file == NULL) {
		goto out;
	}

	replayer_stop_locked();

out:
	k_spin_unlock(&state_lock, spin_key);
}

/*
 * Stops whatever is being replayed and makes the replayer use the given file,
 * starting over from its first stage. Pass NULL to leave the replayer with
 * nothing to play.
 *
 * Once this returns nothing refers to the previously loaded file anymore, so
 * the caller is free to reuse the memory it lives in.
 */
static void replayer_set_file_locked(const struct replay_file *file)
{
	replayer_stop_locked();
	current_file = file;

	if (file != NULL && file->num_stages > 0) {
	        status_led_set_color(LED_STATE_BLUE_FIXED);
	} else {
	        status_led_set_color(LED_STATE_OFF);
	}
}

/*
 * Called from the trace storage thread every time the file on the USB drive
 * changes, with that file open. fp is NULL when the user deleted it.
 */
static void trace_uploaded(struct fs_file_t *fp, size_t size)
{
	int ret;

	k_spinlock_key_t spin_key = k_spin_lock(&state_lock);

	if (fp == NULL) {
		LOG_INF("The replay file was removed, nothing to play\n");
		replayer_set_file_locked(NULL);
		trace_led_set_color(LED_STATE_OFF, LED_TMP_BLINK_NONE);
		goto out_unlock;
	}

	/*
	 * Make sure the file is usable before touching anything: a malformed
	 * upload must not disturb the replay which may be going on right now.
         * Drop the lock before parsing because it could take a while.
	 */
	k_spin_unlock(&state_lock, spin_key);
	ret = replay_parser_check(fp, size);
	spin_key = k_spin_lock(&state_lock);
	bool had_file = current_file != NULL;
	if (ret < 0) {
		LOG_INF("Rejected the uploaded file (%d), keeping the current one\n", ret);
		trace_led_set_color(had_file ? LED_STATE_GREEN_FIXED : LED_STATE_OFF, LED_TMP_BLINK_RED);
		goto out_unlock;
	}

	/*
	 * The parser is about to overwrite the pools the currently loaded file
	 * lives in, so the replayer has to let go of it first. This also stops
	 * the replay, which is what we want since the inputs are changing
	 * under its feet.
	 */
	replayer_set_file_locked(NULL);

	/* Drop the lock again while (re)-parsing */
	k_spin_unlock(&state_lock, spin_key);
	ret = replay_parser_build(fp, size, &uploaded_file);
	spin_key = k_spin_lock(&state_lock);
	if (ret < 0) {
		/*
		 * The check above passed, so either the read failed or the
		 * host rewrote the file in between the two passes.
		 */
		LOG_INF("Failed to parse the uploaded file: %d\n", ret);
		trace_led_set_color(LED_STATE_OFF, LED_TMP_BLINK_RED);
		goto out_unlock;
	}

	replayer_set_file_locked(&uploaded_file);
	trace_led_set_color(LED_STATE_GREEN_FIXED, LED_TMP_BLINK_GREEN);

	LOG_INF("Loaded a replay file with %u stages\n", uploaded_file.num_stages);

out_unlock:
	k_spin_unlock(&state_lock, spin_key);
}

static void button_callback(struct input_event *evt, void *user_data)
{
	if (evt->type != INPUT_EV_KEY) {
		/* Ignore non-key events. */
		return;
	}

	if (evt->value == 0) {
		/* Ignored released keys. */
		return;
	}

	switch (evt->code) {
	case INPUT_KEY_0:
		/* Play trace 0. */
		replayer_enqueue_next_stage(0);
		break;

	case INPUT_KEY_1:
		/* Play trace 1. */
		replayer_enqueue_next_stage(1);
		break;

	case INPUT_KEY_2:
		/* Play trace 2. */
		replayer_enqueue_next_stage(2);
		break;

	case INPUT_KEY_S:
		/* Stop replaying now. */
		replayer_immediate_stop();
		break;

	default:
		break;
	}
}
INPUT_CALLBACK_DEFINE(NULL, button_callback, NULL);

static struct gpio_callback select_callback_data;

/* Called when there is a rising edge on the console's SELECT pin. */
static void select_edge_handler(const struct device *port, struct gpio_callback *cb, gpio_port_pins_t pins)
{
	k_spinlock_key_t spin_key = k_spin_lock(&state_lock);

	if (pins & BIT(port1_select_gpio.pin)) {
		/* The console did something, so it didn't reset yet. Delay the reset work. */
		k_work_reschedule(&reset_work, reset_timeout);
	}

	k_spin_unlock(&state_lock, spin_key);
}

static int replayer_configure_otp(void)
{
	const uint32_t OTP_SW_LOCK_RO = (OTP_SW_LOCK0_NSEC_VALUE_READ_ONLY << OTP_SW_LOCK0_NSEC_LSB)
		| (OTP_SW_LOCK0_SEC_VALUE_READ_ONLY << OTP_SW_LOCK0_SEC_LSB);

	/* Make the entire OTP read-only until the next reset. */
	for (uint32_t i = 0; i < ARRAY_SIZE(otp_hw->sw_lock); i++) {
		otp_hw->sw_lock[i] = OTP_SW_LOCK_RO;
	}

#ifdef CONFIG_REPLAYER_DEBUG_IMAGE
	/* Enable the debug port in debug builds. */
	otp_hw->debugen = OTP_DEBUGEN_BITS;
#endif

	/* Then lock the state of DEBUGEN until the next reset. */
	otp_hw->debugen_lock = OTP_DEBUGEN_LOCK_BITS;

	return 0;
}
SYS_INIT(replayer_configure_otp, EARLY, 0);

int main(void)
{
	int ret;

	/* Initialize the watchdog. */
	task_wdt_init(DEVICE_DT_GET(DT_NODELABEL(wdt0)));

	/*
	 * Bring up the drive the user uploads new input to. This is done
	 * before anything else so that the replayer can still be talked to
	 * over USB if the rest of the initialization fails.
	 */
	trace_storage_set_callback(trace_uploaded);

	ret = trace_storage_init();
	if (ret < 0) {
		LOG_ERR("Failed to initialize the trace storage: %d\n", ret);
		return ret;
	}

	ret = usb_start();
	if (ret < 0) {
		LOG_ERR("Failed to start USB: %d\n", ret);
		return ret;
	}

	if (!gpio_is_ready_dt(&replay_en_gpio)) {
		LOG_ERR("Replay GPIO is not ready: %s\n", replay_en_gpio.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&replay_en_gpio, GPIO_OUTPUT_INACTIVE);

	if (!gpio_is_ready_dt(&port1_select_gpio)) {
		LOG_ERR("Port1 select GPIO is not ready: %s\n", port1_select_gpio.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&port1_select_gpio, GPIO_INPUT);

	gpio_pin_interrupt_configure_dt(&port1_select_gpio, GPIO_INT_EDGE_RISING);
	gpio_init_callback(&select_callback_data, select_edge_handler, BIT(port1_select_gpio.pin));
	gpio_add_callback_dt(&port1_select_gpio, &select_callback_data);

	k_work_schedule(&reset_work, reset_timeout);

	return 0;
}
