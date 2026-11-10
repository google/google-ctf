/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * USB device configuration for the replayer.
 *
 * The replayer shows up as a single mass storage device backed by the RAM disk
 * managed by trace_storage.c, which is how the user uploads the input to
 * replay.
 */

#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/class/usbd_msc.h>
#include <zephyr/usb/usbd.h>

#include "trace_storage.h"
#include "usb.h"

LOG_MODULE_REGISTER(replayer_usb, LOG_LEVEL_INF);

#define REPLAYER_USB_VID 0x18d1
#define REPLAYER_USB_PID 0x1002

/* bMaxPower is expressed in 2 mA units. */
#define REPLAYER_USB_MAX_POWER (250 / 2)

USBD_DEVICE_DEFINE(replayer_usbd, DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)), REPLAYER_USB_VID,
		   REPLAYER_USB_PID);

USBD_DESC_LANG_DEFINE(replayer_lang);
USBD_DESC_MANUFACTURER_DEFINE(replayer_mfr, "Google");
USBD_DESC_PRODUCT_DEFINE(replayer_product, "Hackceler8 2026 Replayer");
/*
 * A fixed serial number instead of the chip's unique identifier: that one is
 * stored in the flash, and the Pico HAL reads it by running code out of a RAM
 * buffer, which the MPU layout in src/mpu_regions.c does not allow and secure
 * boot should not allow either. There is only ever one replayer on a bench.
 */
USBD_DESC_STRING_DEFINE(replayer_sn, "0001", USBD_DUT_STRING_SERIAL_NUMBER);

USBD_DESC_CONFIG_DEFINE(replayer_cfg_desc, "Replayer configuration");

/* The replayer is powered by the console, i.e. not self powered. */
USBD_CONFIGURATION_DEFINE(replayer_config, 0, REPLAYER_USB_MAX_POWER, &replayer_cfg_desc);

/* The drive the user drops the recorded input onto. */
USBD_DEFINE_MSC_LUN(traces, TRACE_STORAGE_DISK_NAME, "Google", "Replayer", "1.00");

int usb_start(void)
{
	int ret;

	ret = usbd_add_descriptor(&replayer_usbd, &replayer_lang);
	if (ret != 0) {
		LOG_ERR("failed to add the language descriptor: %d", ret);
		return ret;
	}

	ret = usbd_add_descriptor(&replayer_usbd, &replayer_mfr);
	if (ret != 0) {
		LOG_ERR("failed to add the manufacturer descriptor: %d", ret);
		return ret;
	}

	ret = usbd_add_descriptor(&replayer_usbd, &replayer_product);
	if (ret != 0) {
		LOG_ERR("failed to add the product descriptor: %d", ret);
		return ret;
	}

	ret = usbd_add_descriptor(&replayer_usbd, &replayer_sn);
	if (ret != 0) {
		LOG_ERR("failed to add the serial number descriptor: %d", ret);
		return ret;
	}

	/* The RP2350 USB device controller is full speed only. */
	ret = usbd_add_configuration(&replayer_usbd, USBD_SPEED_FS, &replayer_config);
	if (ret != 0) {
		LOG_ERR("failed to add the configuration: %d", ret);
		return ret;
	}

	ret = usbd_register_all_classes(&replayer_usbd, USBD_SPEED_FS, 1, NULL);
	if (ret != 0) {
		LOG_ERR("failed to register the USB classes: %d", ret);
		return ret;
	}

	/* Take the class codes from the interface descriptors. */
	ret = usbd_device_set_code_triple(&replayer_usbd, USBD_SPEED_FS, 0, 0, 0);
	if (ret != 0) {
		LOG_ERR("failed to set the class codes: %d", ret);
		return ret;
	}

	ret = usbd_init(&replayer_usbd);
	if (ret != 0) {
		LOG_ERR("failed to initialize the USB device: %d", ret);
		return ret;
	}

	ret = usbd_enable(&replayer_usbd);
	if (ret != 0) {
		LOG_ERR("failed to enable the USB device: %d", ret);
		return ret;
	}

	return 0;
}
