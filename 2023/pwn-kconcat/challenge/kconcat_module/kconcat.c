// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_ERR */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/kallsyms.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>

#define DEVICE_NAME "kconcat"
#define CTF_MAJOR 337

#define MAX_SEGMENT 10
#define MAX_MESSAGE_SIZE 512

static struct mutex global_mutex;
static struct list_head fds;

struct concat_segment {
	int is_file;
	char message_or_filename[MAX_MESSAGE_SIZE];
};

struct fd_info {
	struct list_head list;
	struct mutex lock;
	int is_admin;
	int segment_count;
	struct concat_segment *segments[MAX_SEGMENT];
};

static int module_open(struct inode *inode, struct file *file)
{
	struct fd_info *info = kzalloc(sizeof(struct fd_info), GFP_KERNEL);

	if (!info)
		return -ENOMEM;

    mutex_init(&info->lock);
	file->private_data = info;

	mutex_lock(&global_mutex);
	list_add(&info->list, &fds);
	mutex_unlock(&global_mutex);

	return 0;
}

static noinline long read_file(char *filename, char *buffer, size_t buffer_size)
{
	struct file *f;
	ssize_t read;
	loff_t pos;

	f = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	pos = 0;
	read = kernel_read(f, buffer, buffer_size, &pos);
	filp_close(f, NULL);
	return read;
}

static ssize_t module_read(struct file *file,
                           char __user *buf, size_t count,
                           loff_t *f_pos)
{
	struct fd_info *info = (struct fd_info *) file->private_data;
	struct concat_segment *segment;
	size_t read, read_total = 0, segment_total = 0, segment_pos, segment_size;

	mutex_lock(&info->lock);

	for (int i = 0; i < info->segment_count; i++) {
		if (count == 0)
			break;

		segment = info->segments[i];
		if (!segment)
			continue;

		if (segment->is_file) {
			read = read_file(segment->message_or_filename, segment->message_or_filename, sizeof(segment->message_or_filename) - 1);
			if (read >= 0)
				segment->is_file = 0;
		}

		segment_size = strlen(segment->message_or_filename);
		segment_pos = *f_pos - segment_total;
		segment_total += segment_size;
		if (segment_pos > segment_size)
			continue;

		read = min(count, segment_size - segment_pos);
		if (copy_to_user(buf, &segment->message_or_filename[segment_pos], read)) {
			mutex_unlock(&info->lock);
			return -EINVAL;
		}

		read_total += read;
		buf += read;
		count -= read;
		*f_pos += read;
	}

	mutex_unlock(&info->lock);

	return read_total;
}

static noinline struct concat_segment *add_segment(struct fd_info *info)
{
	struct concat_segment *segment;

	if (info->segment_count >= MAX_SEGMENT)
		return ERR_PTR(-ENOSPC);

	segment = kzalloc(sizeof(*segment), GFP_KERNEL);
	info->segments[info->segment_count++] = segment;
	return segment;
}

static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
	struct fd_info *info = (struct fd_info *) file->private_data;
	struct concat_segment *segment;
	ssize_t retval = -1;

	if (count >= MAX_MESSAGE_SIZE)
		return -EFBIG;

	mutex_lock(&info->lock);
	segment = add_segment(info);
	if (IS_ERR(segment)) {
		retval = PTR_ERR(segment);
		goto unlock;
	}

	if (copy_from_user(segment->message_or_filename, buf, count))
		retval = -EINVAL;
	else
		retval = count;

unlock:
	mutex_unlock(&info->lock);
	return retval;
}

static int module_close(struct inode *inode, struct file *file)
{
	struct fd_info *info = (struct fd_info *) file->private_data;

	mutex_lock(&global_mutex);
	list_del(&info->list);
	mutex_unlock(&global_mutex);

	for (int i = 0; i < info->segment_count; i++)
		kfree(info->segments[i]);

	kfree(info);

	return 0;
}

static noinline long add_template(struct fd_info *info, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct concat_segment *segment;
	char template_name[16] = { 0 };

	if (copy_from_user(&template_name[0], uptr, sizeof(template_name) - 1))
		return -EINVAL;

	for (int i = 0; i < strlen(template_name); i++)
		if (!isalpha(template_name[i]))
			return -EINVAL;

	segment = add_segment(info);
	if (IS_ERR(segment))
		return PTR_ERR(segment);

	snprintf(segment->message_or_filename, sizeof(segment->message_or_filename) - 1,
		"/etc/kconcat/message-templates/%s", template_name);
	segment->is_file = 1;

	return 0;
}

static noinline long moderation(struct fd_info *admin_info, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	char blocked[16] = { 0 };
	struct fd_info *info;
	struct concat_segment *segment;

	if (!admin_info->is_admin)
		return -EPERM;

	if (copy_from_user(blocked, uptr, sizeof(blocked) - 1))
		return -EINVAL;

	mutex_lock(&global_mutex);

	list_for_each_entry(info, &fds, list) {
		for (int i = 0; i < info->segment_count; i++) {
			segment = info->segments[i];
			if (info->segments[i] && strnstr(segment->message_or_filename, blocked, MAX_MESSAGE_SIZE)) {
				info->segments[i] = 0;
				kfree(segment);
			}
		}
    }

	mutex_unlock(&global_mutex);

	return 0;
}

static noinline long module_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct fd_info *info = (struct fd_info *) file->private_data;
	long retval;

	mutex_lock(&info->lock);

	if (capable(CAP_SYS_ADMIN))
		info->is_admin = 1;

	if (cmd == 0x1234)
		retval = add_template(info, arg);
	else if (cmd == 0x1337)
		retval = moderation(info, arg);
	else
		retval = -EINVAL;

	mutex_unlock(&info->lock);

	return retval;
}

static struct file_operations module_fops = {
	.owner          = THIS_MODULE,
	.read           = module_read,
	.write          = module_write,
	.open           = module_open,
	.unlocked_ioctl = module_ioctl,
	.release        = module_close,
};

static struct cdev c_dev;

static int __init kernelctf_module_init(void)
{
	INIT_LIST_HEAD(&fds);
    mutex_init(&global_mutex);

	if (register_chrdev_region(MKDEV(CTF_MAJOR, 0), 1, DEVICE_NAME))
		return -EBUSY;

	cdev_init(&c_dev, &module_fops);
	c_dev.owner = THIS_MODULE;

	if (cdev_add(&c_dev, MKDEV(CTF_MAJOR, 0), 1)) {
		unregister_chrdev_region(MKDEV(CTF_MAJOR, 0), 1);
		return -EBUSY;
	}

	return 0;
}

static void __exit kernelctf_module_exit(void)
{
	cdev_del(&c_dev);
	unregister_chrdev_region(MKDEV(CTF_MAJOR, 0), 1);
}

module_init(kernelctf_module_init);
module_exit(kernelctf_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("poprdi");
MODULE_DESCRIPTION("kernelctf");
