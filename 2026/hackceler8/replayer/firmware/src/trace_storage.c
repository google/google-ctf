/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Storage backend for the traces uploaded by the user.
 *
 * The replayer exposes a small FAT formatted RAM disk to the host as a USB
 * mass storage device. The disk is created (and populated with a README) at
 * boot, the host is then free to do whatever it wants with it.
 *
 * Every write coming from the host is signalled to a worker thread. Once the
 * host has stopped writing for a while (i.e. the file copy is over and the
 * directory entries have been updated) the worker mounts the volume and looks
 * for a file which was not there the last time it looked. It then hands that
 * file, open, to whoever registered a callback: the firmware keeps no copy of
 * its contents, which for a file of this size would cost more RAM than the
 * parsed replay itself.
 *
 * The firmware only ever mounts the volume from that single thread, and only
 * while the host is idle, so that FatFs never caches state which the host
 * invalidates behind its back.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/drivers/disk.h>
#include <zephyr/fs/fs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>
#include <zephyr/task_wdt/task_wdt.h>

#include <ff.h>

#include "trace_storage.h"

LOG_MODULE_REGISTER(trace_storage, LOG_LEVEL_INF);

/*
 * USB mass storage only supports power of two sector sizes and the FAT
 * bootsector can only describe sectors of at least 512 bytes, which also
 * happens to be the largest sector size FatFs is configured for in Zephyr.
 */
#define DISK_SECTOR_SIZE 512U
#define DISK_SECTOR_COUNT CONFIG_TRACE_STORAGE_DISK_SECTORS

/* FatFs volume path, the mount point is the same with a leading slash. */
#define FAT_VOLUME TRACE_STORAGE_DISK_NAME ":"
#define MOUNT_POINT "/" FAT_VOLUME

/* Label shown by the host for the drive. At most 11 uppercase characters. */
#define VOLUME_LABEL "REPLAYER"

#define README_NAME "README.TXT"
#define README_PATH MOUNT_POINT "/" README_NAME

/* How long the host has to keep quiet before we look at the volume. */
#define SETTLE_TIME K_MSEC(500)

/* Number of files (besides the README) we keep track of between two scans. */
#define MAX_TRACKED_FILES 8

static const uint32_t TRACE_STORAGE_WDT_TIMEOUT_MS = 500;

struct tracked_file {
	char name[MAX_FILE_NAME + 1];
	size_t size;
};

/* Backing store of the FAT volume exported over USB. */
static K_MUTEX_DEFINE(disk_buf_mutex);
static uint8_t disk_buf[DISK_SECTOR_COUNT * DISK_SECTOR_SIZE];

/* The file the user uploaded last. Its contents stay on the volume. */
static size_t trace_size;
static char trace_name[MAX_FILE_NAME + 1];

/* Bumped every time the file the user uploaded changes. */
static uint32_t trace_generation;

static trace_storage_cb_t upload_cb;

/* Files which were on the volume the last time we scanned it. */
static struct tracked_file known_files[MAX_TRACKED_FILES];
static size_t num_known_files;

/* Signalled by the disk driver every time the host writes to the disk. */
static K_SEM_DEFINE(host_wrote, 0, 1);

/* Set once the volume is ready, the host can only write after that. */
static atomic_t watching;

static FATFS fat_fs;
static struct fs_mount_t mount_point = {
	.type = FS_FATFS,
	.fs_data = &fat_fs,
	.mnt_point = MOUNT_POINT,
	/*
	 * Never reformat behind the user's back, we want to know (and log)
	 * when the volume got corrupted.
	 */
	.flags = FS_MOUNT_FLAG_NO_FORMAT,
};

/*
 * The disk is a plain chunk of RAM. The only thing this driver does on top of
 * what the generic Zephyr RAM disk driver does is telling us when the host
 * wrote something.
 */

static int disk_op_status(struct disk_info *disk)
{
	ARG_UNUSED(disk);

	return DISK_STATUS_OK;
}

static int disk_op_read(struct disk_info *disk, uint8_t *buf, uint32_t sector, uint32_t count)
{
	ARG_UNUSED(disk);

	if ((sector + count) > DISK_SECTOR_COUNT || (sector + count) < sector) {
		LOG_ERR("read of %u sectors at %u is out of range", count, sector);
		return -EIO;
	}

	k_mutex_lock(&disk_buf_mutex, K_FOREVER);
	memcpy(buf, &disk_buf[sector * DISK_SECTOR_SIZE], count * DISK_SECTOR_SIZE);
	k_mutex_unlock(&disk_buf_mutex);

	return 0;
}

static int disk_op_write(struct disk_info *disk, const uint8_t *buf, uint32_t sector,
			 uint32_t count)
{
	ARG_UNUSED(disk);

	if ((sector + count) > DISK_SECTOR_COUNT || (sector + count) < sector) {
		LOG_ERR("write of %u sectors at %u is out of range", count, sector);
		return -EIO;
	}

	k_mutex_lock(&disk_buf_mutex, K_FOREVER);
	memcpy(&disk_buf[sector * DISK_SECTOR_SIZE], buf, count * DISK_SECTOR_SIZE);

	if (atomic_get(&watching)) {
		k_sem_give(&host_wrote);
	}
	k_mutex_unlock(&disk_buf_mutex);

	return 0;
}

static int disk_op_erase(struct disk_info *disk, uint32_t sector, uint32_t count)
{
	ARG_UNUSED(disk);

	if ((sector + count) > DISK_SECTOR_COUNT || (sector + count) < sector) {
		LOG_ERR("erase of %u sectors at %u is out of range", count, sector);
		return -EIO;
	}

	k_mutex_lock(&disk_buf_mutex, K_FOREVER);
	memset(&disk_buf[sector * DISK_SECTOR_SIZE], 0, count * DISK_SECTOR_SIZE);

	if (atomic_get(&watching)) {
		k_sem_give(&host_wrote);
	}
	k_mutex_unlock(&disk_buf_mutex);

	return 0;
}

static int disk_op_ioctl(struct disk_info *disk, uint8_t cmd, void *buf)
{
	ARG_UNUSED(disk);

	switch (cmd) {
	case DISK_IOCTL_GET_SECTOR_COUNT:
		*(uint32_t *)buf = DISK_SECTOR_COUNT;
		break;

	case DISK_IOCTL_GET_SECTOR_SIZE:
		*(uint32_t *)buf = DISK_SECTOR_SIZE;
		break;

	case DISK_IOCTL_GET_ERASE_BLOCK_SZ:
		/* RAM has no erase blocks. */
		*(uint32_t *)buf = 1U;
		break;

	case DISK_IOCTL_CTRL_SYNC:
	case DISK_IOCTL_CTRL_INIT:
	case DISK_IOCTL_CTRL_DEINIT:
		/* Nothing to do, the disk is always ready. */
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int disk_op_init(struct disk_info *disk)
{
	ARG_UNUSED(disk);

	return 0;
}

static const struct disk_operations disk_ops = {
	.init = disk_op_init,
	.status = disk_op_status,
	.read = disk_op_read,
	.write = disk_op_write,
	.erase = disk_op_erase,
	.ioctl = disk_op_ioctl,
};

static struct disk_info disk = {
	.name = TRACE_STORAGE_DISK_NAME,
	.ops = &disk_ops,
};

static bool name_equals(const char *a, const char *b)
{
	/* FAT is case insensitive, and so are the names it reports back. */
	for (; *a != '\0' && *b != '\0'; a++, b++) {
		char ca = (*a >= 'a' && *a <= 'z') ? (*a - 'a' + 'A') : *a;
		char cb = (*b >= 'a' && *b <= 'z') ? (*b - 'a' + 'A') : *b;

		if (ca != cb) {
			return false;
		}
	}

	return *a == *b;
}

/*
 * Files which the user did not upload: the README we created ourselves and the
 * metadata operating systems like to sprinkle over removable drives, which is
 * always hidden (i.e. its name starts with a dot).
 */
static bool is_ignored(const char *name)
{
	return name[0] == '.' || name_equals(name, README_NAME);
}

static bool was_known(const struct tracked_file *file)
{
	for (size_t i = 0; i < num_known_files; i++) {
		if (known_files[i].size == file->size &&
		    name_equals(known_files[i].name, file->name)) {
			return true;
		}
	}

	return false;
}

static void forget_trace(void)
{
	trace_size = 0;
	trace_name[0] = '\0';
	trace_generation++;
}

/*
 * Takes note of the file the user dropped in. Its contents are not read here:
 * they are read straight off the volume when the file is handed to the
 * callback, so that no buffer the size of a replay is needed.
 */
static int load_trace(const struct tracked_file *file)
{
	if (file->size > CONFIG_TRACE_STORAGE_MAX_FILE_SIZE) {
		LOG_ERR("'%s' is too big (%zu bytes, max %u)", file->name, file->size,
			(unsigned int)CONFIG_TRACE_STORAGE_MAX_FILE_SIZE);
		return -EFBIG;
	}

	trace_size = file->size;
	strncpy(trace_name, file->name, sizeof(trace_name) - 1);
	trace_name[sizeof(trace_name) - 1] = '\0';
	trace_generation++;

	LOG_INF("picked up '%s' (%zu bytes)", trace_name, trace_size);

	return 0;
}

/*
 * Looks at the contents of the volume and picks up the file the user dropped
 * in, if any. Called with the volume mounted.
 */
static void find_new_trace(void)
{
	struct tracked_file found[MAX_TRACKED_FILES];
	size_t num_found = 0;
	bool trace_still_there = false;
	int new_file = -1;
	struct fs_dir_t dir;
	int ret;

	fs_dir_t_init(&dir);

	ret = fs_opendir(&dir, MOUNT_POINT);
	if (ret < 0) {
		LOG_ERR("failed to open the root directory: %d", ret);
		return;
	}

	while (num_found < ARRAY_SIZE(found)) {
		struct fs_dirent entry;

		ret = fs_readdir(&dir, &entry);
		if (ret < 0) {
			LOG_ERR("failed to read the root directory: %d", ret);
			break;
		}

		if (entry.name[0] == '\0') {
			/* End of the directory. */
			break;
		}

		if (entry.type != FS_DIR_ENTRY_FILE || is_ignored(entry.name)) {
			continue;
		}

		strncpy(found[num_found].name, entry.name, sizeof(found[num_found].name) - 1);
		found[num_found].name[sizeof(found[num_found].name) - 1] = '\0';
		found[num_found].size = entry.size;

		if (!was_known(&found[num_found]) && new_file < 0) {
			new_file = num_found;
		}

		if (name_equals(found[num_found].name, trace_name)) {
			trace_still_there = true;
		}

		num_found++;
	}

	fs_closedir(&dir);

	if (new_file >= 0) {
		load_trace(&found[new_file]);
	} else if (trace_size > 0 && !trace_still_there) {
		LOG_INF("'%s' was deleted", trace_name);
		forget_trace();
	}

	/* Remember what the volume looks like so that we can diff it later. */
	memcpy(known_files, found, num_found * sizeof(found[0]));
	num_known_files = num_found;
}

static int create_readme(void)
{
	static char readme[768];
	struct fs_file_t fp;
	int len;
	int ret;

	len = snprintf(readme, sizeof(readme),
		       "Hackceler8 2026 replayer\r\n"
		       "========================\r\n"
		       "\r\n"
		       "Drop the file with the inputs you want to replay onto this drive\r\n"
		       "and the replayer will load it into its memory as soon as the copy\r\n"
		       "is over. Dropping another file replaces the previously loaded one.\r\n"
		       "\r\n"
		       "A file can be at most %u bytes long.\r\n"
		       "\r\n"
		       "This drive lives in the replayer's RAM: its contents, including\r\n"
		       "this file, are lost when the replayer is power cycled.\r\n",
		       (unsigned int)CONFIG_TRACE_STORAGE_MAX_FILE_SIZE);
	if (len < 0 || len >= (int)sizeof(readme)) {
		return -ENOMEM;
	}

	fs_file_t_init(&fp);

	ret = fs_open(&fp, README_PATH, FS_O_CREATE | FS_O_WRITE);
	if (ret < 0) {
		LOG_ERR("failed to create " README_PATH ": %d", ret);
		return ret;
	}

	ret = fs_write(&fp, readme, len);
	if (ret < 0) {
		LOG_ERR("failed to write " README_PATH ": %d", ret);
	}

	fs_close(&fp);

	return ret < 0 ? ret : 0;
}

/* Creates an empty volume with just the README on it. */
static int format_volume(void)
{
	MKFS_PARM opt = {
		/*
		 * The volume is way too small for FAT32 (which needs at least
		 * 65525 clusters) so let FatFs pick between FAT12 and FAT16.
		 * Like most removable drives of this size the volume is not
		 * partitioned (SFD, "super floppy").
		 */
		.fmt = FM_FAT | FM_SFD,
		/* One copy of the allocation table is plenty. */
		.n_fat = 1,
		/* Enough room for the README and the operating system's junk. */
		.n_root = 64,
		/* Let FatFs figure out the cluster size and the alignment. */
		.au_size = 0,
		.align = 0,
	};
	int ret;

	ret = fs_mkfs(FS_FATFS, (uintptr_t)FAT_VOLUME, &opt, 0);
	if (ret < 0) {
		LOG_ERR("failed to format the volume: %d", ret);
		return ret;
	}

	ret = fs_mount(&mount_point);
	if (ret < 0) {
		LOG_ERR("failed to mount the volume: %d", ret);
		return ret;
	}

	if (f_setlabel(FAT_VOLUME VOLUME_LABEL) != FR_OK) {
		/* Not fatal, the drive just shows up unnamed. */
		LOG_WRN("failed to set the volume label");
	}

	ret = create_readme();

	fs_unmount(&mount_point);

	return ret;
}

static void scan_volume(void)
{
	int ret;

	ret = fs_mount(&mount_point);
	if (ret < 0) {
		/*
		 * The host managed to corrupt the volume (or formatted it
		 * itself with something we cannot read). Start over.
		 */
		LOG_ERR("failed to mount the volume (%d), reformatting it", ret);
		forget_trace();
		num_known_files = 0;
		format_volume();
		return;
	}

	find_new_trace();

	fs_unmount(&mount_point);
}

/*
 * Hands the file the user uploaded to the callback, mounting the volume and
 * opening the file for the duration of the call so that the callback can read
 * the contents itself. Passes NULL when there is no file to play.
 */
static void notify_upload(void)
{
	char path[sizeof(MOUNT_POINT) + 1 + MAX_FILE_NAME];
	struct fs_file_t fp;
	int ret;

	if (upload_cb == NULL) {
		return;
	}

	if (trace_size == 0) {
		upload_cb(NULL, 0);
		return;
	}

	ret = fs_mount(&mount_point);
	if (ret < 0) {
		LOG_ERR("failed to mount the volume: %d", ret);
		return;
	}

	snprintf(path, sizeof(path), MOUNT_POINT "/%s", trace_name);

	fs_file_t_init(&fp);

	ret = fs_open(&fp, path, FS_O_READ);
	if (ret < 0) {
		LOG_ERR("failed to open '%s': %d", path, ret);
		/*
		 * Whatever the host left on the volume is not readable, so
		 * stop calling it the uploaded file. The callback is not told
		 * anything, which leaves the replayer with the file it already
		 * had.
		 */
		forget_trace();
	} else {
		upload_cb(&fp, trace_size);
		fs_close(&fp);
	}

	fs_unmount(&mount_point);
}

static void storage_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		uint32_t old_generation = trace_generation;

		/* Wait for the host to touch the disk. */
		k_sem_take(&host_wrote, K_FOREVER);

		/*
		 * Writing a file takes several transfers, and the directory
		 * entry is only updated at the end of the copy. Wait for the
		 * host to be done before looking at the volume.
		 */
		while (k_sem_take(&host_wrote, SETTLE_TIME) == 0) {
		}

		/*
		 * Make sure that the watchdog resets the microcontroller if
		 * for whatever reason this gets stuck parsing the trace
		 */
		int wd = task_wdt_add(TRACE_STORAGE_WDT_TIMEOUT_MS, NULL, NULL);

		k_mutex_lock(&disk_buf_mutex, K_FOREVER);
		scan_volume();

		if (trace_generation != old_generation) {
			notify_upload();
		}
		k_mutex_unlock(&disk_buf_mutex);

		/* Stop the watchdog now because the work is done. */
		task_wdt_delete(wd);
	}
}

K_THREAD_DEFINE(trace_storage_thread, CONFIG_TRACE_STORAGE_THREAD_STACK_SIZE, storage_thread, NULL,
		NULL, NULL, K_PRIO_PREEMPT(10), 0, 0);

int trace_storage_init(void)
{
	int ret;

	ret = disk_access_register(&disk);
	if (ret < 0) {
		LOG_ERR("failed to register the disk: %d", ret);
		return ret;
	}

	ret = format_volume();
	if (ret < 0) {
		return ret;
	}

	LOG_INF("%u KiB trace upload drive ready", (unsigned int)(sizeof(disk_buf) / 1024));

	/* From now on every write to the disk comes from the host. */
	atomic_set(&watching, 1);

	return 0;
}

void trace_storage_set_callback(trace_storage_cb_t cb)
{
	upload_cb = cb;
}
