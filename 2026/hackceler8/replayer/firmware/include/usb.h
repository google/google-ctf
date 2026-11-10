/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

/*
 * Configures and enables the USB device. The replayer exposes a single
 * interface, a mass storage device backed by the trace storage RAM disk.
 *
 * trace_storage_init() must have been called before this.
 */
int usb_start(void);
