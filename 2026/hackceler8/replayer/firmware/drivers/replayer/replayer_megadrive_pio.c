/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hardware/pio_instructions.h"
#include "zephyr/sys/__assert.h"
#define DT_DRV_COMPAT google_megadrive_replayer_pio

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <drivers/replayer/megadrive.h>

#include <hardware/pio.h>
#include <hardware/gpio.h>

LOG_MODULE_REGISTER(replayer_md_pio, CONFIG_LOG_DEFAULT_LEVEL);

/* PIO assembly instructions for Mega Drive Controller protocol */
static const uint16_t megadrive_pio_instructions[] = {
        0x20a0, /* 0: wait 1 pin, 0         (Wait until SELECT is HIGH) */
        0x6006, /* 1: out  pins, 6          (Output B, C, DOWN, LEFT, RIGHT, UP) */
        0x2020, /* 2: wait 0 pin, 0         (Wait until SELECT is LOW) */
        0x7c02, /* 3: out  pins, 2 side 3   (Output A, START; side-set 1 to LEFT, RIGHT) */
};

static const struct pio_program megadrive_pio_program = {
	.instructions = megadrive_pio_instructions,
	.length = ARRAY_SIZE(megadrive_pio_instructions),
	.origin = 0,
};

typedef void (*megadrive_pio_irq_config_func_t)(const struct device *dev);

struct megadrive_pio_config {
	PIO pio;
	uint sm;
	struct gpio_dt_spec select_gpio;
	struct gpio_dt_spec data_gpios[6];
	megadrive_pio_irq_config_func_t irq_config_func;
};

struct megadrive_pio_data {
	const struct device *dev;
	uint offset;
	bool replaying;
	megadrive_pio_next_input_cb_t next_input_cb;
	void *cb_user_data;
};

static void megadrive_pio_enqueue_input(const struct device *dev, uint8_t input)
{
	const struct megadrive_pio_config *config = dev->config;

	/* The Mega Drive polls SELECT once per frame. */
	uint32_t val = ((uint32_t)input);

	__ASSERT(!pio_sm_is_tx_fifo_full(config->pio, config->sm), "tried to write data to a full FIFO");
	pio_sm_put(config->pio, config->sm, val);
}

static int megadrive_pio_start_impl(const struct device *dev)
{
	struct megadrive_pio_data *data = dev->data;
	const struct megadrive_pio_config *config = dev->config;

	if (data->replaying) {
		return 0;
	}

	pio_sm_set_enabled(config->pio, config->sm, true);
	data->replaying = true;

	LOG_INF("Replay started");
	return 0;
}

static int megadrive_pio_stop_impl(const struct device *dev)
{
	const struct megadrive_pio_config *config = dev->config;
	struct megadrive_pio_data *data = dev->data;

	/* Reset the state machine and flush FIFO */
	pio_sm_set_enabled(config->pio, config->sm, false);
	pio_sm_drain_tx_fifo(config->pio, config->sm);
	pio_sm_restart(config->pio, config->sm);

	pio_sm_exec(config->pio, config->sm, pio_encode_jmp(data->offset));

	data->replaying = false;

	return 0;
}

static void megadrive_pio_set_input_callback_impl(const struct device *dev,
						  megadrive_pio_next_input_cb_t cb,
						  void *user_data)
{
	struct megadrive_pio_data *data = dev->data;
	const struct megadrive_pio_config *config = dev->config;

	data->next_input_cb = cb;
	data->cb_user_data = user_data;

	if (cb == NULL) {
		/*
		 * Clear the TXSTALL flag, which is sticky. We only want to start
		 * detecting stalls now that we actually stopped sending data.
		 */
		config->pio->fdebug = 1u << (PIO_FDEBUG_TXSTALL_LSB + config->sm);
	}

	/* Disable interrupt if no callback registered, enable it if registered */
	pio_set_irq0_source_enabled(config->pio, pis_sm0_tx_fifo_not_full, cb != NULL);
}

static void megadrive_pio_tx_isr(const void *arg)
{
	const struct device *dev = (const struct device *)arg;
	struct megadrive_pio_data *data = dev->data;

	if (!data->replaying || data->next_input_cb == NULL) {
		/*
		 * Do nothing in case we get a spurious interrupt, e.g.
		 * because it was latched in the NVIC.
		 */
		return;
	}

	int32_t next_input = data->next_input_cb(data->cb_user_data);
	if (next_input >= 0) {
		megadrive_pio_enqueue_input(dev, (uint8_t)next_input);
	}
}

static bool megadrive_pio_is_drained_impl(const struct device *dev)
{
	const struct megadrive_pio_config *config = dev->config;

	/*
	 * Make sure that not only the FIFO is emtpy but that the SM has also
	 * stalled since we began draining.
	 */
	uint32_t stall_mask = 1u << (PIO_FDEBUG_TXSTALL_LSB + config->sm);
	bool sm_stalled = (config->pio->fdebug & stall_mask) != 0;
	return pio_sm_is_tx_fifo_empty(config->pio, config->sm) && sm_stalled;
}

static const struct megadrive_pio_driver_api megadrive_pio_api = {
	.start = megadrive_pio_start_impl,
	.stop = megadrive_pio_stop_impl,
	.is_drained = megadrive_pio_is_drained_impl,
	.set_input_callback = megadrive_pio_set_input_callback_impl,
};

static int megadrive_pio_init(const struct device *dev)
{
	const struct megadrive_pio_config *config = dev->config;
	struct megadrive_pio_data *data = dev->data;

	data->dev = dev;
	data->replaying = false;

	/* 1. Configure the 6 data output GPIOs (GPIO 0-5) */
	for (int i = 0; i < 6; i++) {
		gpio_pin_t pin = config->data_gpios[i].pin;
		gpio_set_function(pin, pio_get_funcsel(config->pio));
		gpio_set_dir(pin, GPIO_OUT);
		gpio_set_outover(pin, GPIO_OVERRIDE_INVERT);
	}

	/* 2. Configure SELECT input GPIO (GPIO 6) */
	gpio_pin_t sel_pin = config->select_gpio.pin;
	gpio_set_dir(sel_pin, GPIO_IN);

	/* 3. Load the PIO program */
	data->offset = pio_add_program(config->pio, &megadrive_pio_program);

	/* 4. Configure pin directions for state machine */
	pio_sm_set_consecutive_pindirs(config->pio, config->sm,
				       config->data_gpios[0].pin, 6, true);
	pio_sm_set_consecutive_pindirs(config->pio, config->sm,
				       sel_pin, 1, false);

	/* 5. Configure PIO state machine */
	pio_sm_config c = pio_get_default_sm_config();
	sm_config_set_wrap(&c, data->offset + 0, data->offset + 3);
	sm_config_set_out_pins(&c, config->data_gpios[0].pin, 6);
	sm_config_set_in_pins(&c, sel_pin);
	sm_config_set_sideset_pins(&c, config->data_gpios[3].pin); /* LEFT, RIGHT (pins 3-4) */
	/* bit_count here needs to be 3 even though we have 2 sideset pins, because one more bit is required for optional sideset. */
	sm_config_set_sideset(&c, 3, true, false);
	sm_config_set_out_shift(&c, true, true, 8);
	/* Slow down the clock so that the state machine is not affected by spurious SELECT pulses. */
	sm_config_set_clkdiv_int_frac(&c, 16, 0);

	pio_sm_init(config->pio, config->sm, data->offset, &c);

	/* 7. Connect and enable PIO IRQ in Zephyr */
	if (config->irq_config_func != NULL) {
		config->irq_config_func(dev);
	}

	LOG_INF("Mega Drive PIO Replayer initialized on PIO0 SM%u", config->sm);
	return 0;
}

#define MEGADRIVE_PIO_INIT(inst)                                                   \
	static void megadrive_pio_irq_config_##inst(const struct device *dev)     \
	{                                                                               \
		IRQ_CONNECT(DT_IRQ_BY_NAME(DT_INST_PHANDLE(inst, pio), irq0, irq),     \
			    DT_IRQ_BY_NAME(DT_INST_PHANDLE(inst, pio), irq0, priority),\
			    megadrive_pio_tx_isr, DEVICE_DT_INST_GET(inst), 0);       \
		irq_enable(DT_IRQ_BY_NAME(DT_INST_PHANDLE(inst, pio), irq0, irq));     \
	}                                                                               \
                                                                                        \
	static struct megadrive_pio_data megadrive_pio_data_##inst;           \
	static const struct megadrive_pio_config megadrive_pio_cfg_##inst = {  \
		.pio = (PIO)DT_REG_ADDR(DT_INST_PHANDLE(inst, pio)),                    \
		.sm = 0,                                                                \
		.select_gpio = GPIO_DT_SPEC_INST_GET(inst, select_gpios),              \
		.data_gpios = {                                                         \
			GPIO_DT_SPEC_INST_GET_BY_IDX(inst, data_gpios, 0),              \
			GPIO_DT_SPEC_INST_GET_BY_IDX(inst, data_gpios, 1),              \
			GPIO_DT_SPEC_INST_GET_BY_IDX(inst, data_gpios, 2),              \
			GPIO_DT_SPEC_INST_GET_BY_IDX(inst, data_gpios, 3),              \
			GPIO_DT_SPEC_INST_GET_BY_IDX(inst, data_gpios, 4),              \
			GPIO_DT_SPEC_INST_GET_BY_IDX(inst, data_gpios, 5),              \
		},                                                                      \
		.irq_config_func = megadrive_pio_irq_config_##inst,                \
	};                                                                              \
	DEVICE_DT_INST_DEFINE(inst, megadrive_pio_init, NULL,                      \
			      &megadrive_pio_data_##inst,                          \
			      &megadrive_pio_cfg_##inst, POST_KERNEL,              \
			      CONFIG_APPLICATION_INIT_PRIORITY,                         \
			      &megadrive_pio_api);

DT_INST_FOREACH_STATUS_OKAY(MEGADRIVE_PIO_INIT)
