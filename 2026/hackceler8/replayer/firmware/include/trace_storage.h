/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <zephyr/fs/fs.h>

/*
 * Name of the disk which backs the FAT volume exposed to the host over USB
 * mass storage. It has to match one of the volume strings configured with
 * CONFIG_FS_FATFS_CUSTOM_MOUNT_POINTS and is also the disk name referenced by
 * the USB MSC logical unit.
 */
#define TRACE_STORAGE_DISK_NAME "TRACE"

/*
 * Called from the storage thread whenever the file uploaded by the user
 * changes. fp is that file, open for reading and size bytes long; it is NULL
 * when the file was removed from the drive.
 *
 * The firmware does not keep a copy of the contents, so they have to be read
 * through fp before returning: the file is closed and the volume unmounted as
 * soon as the callback is over. Note that the host can rewrite the sectors the
 * file lives in at any time, so two reads of the same offset may not return
 * the same bytes.
 */
typedef void (*trace_storage_cb_t)(struct fs_file_t *fp, size_t size);

/*
 * Formats the RAM disk which backs the USB mass storage device, populates it
 * with the README and starts watching it for uploads.
 *
 * Must be called before the USB device is enabled.
 */
int trace_storage_init(void);


/*
 * Registers a callback invoked every time the uploaded file changes. Pass NULL
 * to unregister. The callback runs in the context of the storage thread.
 */
void trace_storage_set_callback(trace_storage_cb_t cb);
