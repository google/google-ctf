/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_REPLAYER_MEGADRIVE_H_
#define ZEPHYR_INCLUDE_DRIVERS_REPLAYER_MEGADRIVE_H_

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*megadrive_pio_next_input_cb_t)(void *user_data);

__subsystem struct megadrive_pio_driver_api {
	int (*start)(const struct device *dev);
	int (*stop)(const struct device *dev);
	bool (*is_drained)(const struct device *dev);
	void (*set_input_callback)(const struct device *dev,
				   megadrive_pio_next_input_cb_t cb,
				   void *user_data);
};

static inline int megadrive_pio_start(const struct device *dev)
{
	const struct megadrive_pio_driver_api *api = (const struct megadrive_pio_driver_api *)dev->api;

	return api->start(dev);
}

static inline int megadrive_pio_stop(const struct device *dev)
{
	const struct megadrive_pio_driver_api *api = (const struct megadrive_pio_driver_api *)dev->api;

	return api->stop(dev);
}

static inline bool megadrive_pio_is_drained(const struct device *dev)
{
	const struct megadrive_pio_driver_api *api = (const struct megadrive_pio_driver_api *)dev->api;

	return api->is_drained(dev);
}

/**
 * @brief Register a callback to supply input data when the state machine FIFO needs refilling.
 *
 * @param dev Replayer device instance.
 * @param cb Callback function.
 * @param user_data Context pointer passed to callback.
 */
static inline void megadrive_pio_set_input_callback(const struct device *dev,
					       megadrive_pio_next_input_cb_t cb,
					       void *user_data)
{
	const struct megadrive_pio_driver_api *api = (const struct megadrive_pio_driver_api *)dev->api;

	api->set_input_callback(dev, cb, user_data);
}

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_DRIVERS_REPLAYER_MEGADRIVE_H_ */
