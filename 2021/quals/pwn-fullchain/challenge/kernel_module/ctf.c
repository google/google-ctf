/*
  Copyright 2021 Google LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>

#define CTF_MAJOR 385

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_AUTHOR("Matteo Rizzo <matteorizzo@google.com>");
MODULE_DESCRIPTION("Exploit me");
MODULE_LICENSE("Apache-2.0");

static ssize_t ctf_read(struct file *f, char __user *data, size_t size, loff_t *off);
static ssize_t ctf_write(struct file *f, const char __user *data, size_t size, loff_t *off);
static ssize_t ctf_ioctl(struct file *, unsigned int cmd, unsigned long arg);
static int ctf_open(struct inode *inode, struct file *f);
static int ctf_release(struct inode *inode, struct file *f);

struct ctf_data {
  char *mem;
  size_t size;
};

static struct cdev ctf_cdev;
static const struct file_operations ctf_fops = {
  .owner = THIS_MODULE,
  .open = ctf_open,
  .release = ctf_release,
  .read = ctf_read,
  .write = ctf_write,
  .unlocked_ioctl = ctf_ioctl,
};

static ssize_t ctf_read(struct file *f, char __user *data, size_t size, loff_t *off)
{
  struct ctf_data *ctf_data = f->private_data;
  if (size > ctf_data->size) {
    return -EINVAL;
  }

  if (copy_to_user(data, ctf_data->mem, size)) {
    return -EFAULT;
  }

  return size;
}

static ssize_t ctf_write(struct file *f, const char __user *data, size_t size, loff_t *off)
{
  struct ctf_data *ctf_data = f->private_data;
  if (size > ctf_data->size) {
    return -EINVAL;
  }

  if (copy_from_user(ctf_data->mem, data, size)) {
    return -EFAULT;
  }

  return size;
}

static ssize_t ctf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  struct ctf_data *data = f->private_data;
  char *mem;

  switch(cmd) {
  case 1337:
    if (arg > 2000) {
      return -EINVAL;
    }

    mem = kmalloc(arg, GFP_KERNEL);
    if (mem == NULL) {
      return -ENOMEM;
    }

    data->mem = mem;
    data->size = arg;
    break;

  case 1338:
    kfree(data->mem);
    break;

  default:
    return -ENOTTY;
  }

  return 0;
}

static int ctf_open(struct inode *inode, struct file *f)
{
  struct ctf_data *data = kzalloc(sizeof(struct ctf_data), GFP_KERNEL);
  if (data == NULL) {
    return -ENOMEM;
  }

  f->private_data = data;

  return 0;
}

static int ctf_release(struct inode *inode, struct file *f)
{
  kfree(f->private_data);
  return 0;
}

static int __init ctf_init_module(void)
{
  int err = register_chrdev_region(MKDEV(CTF_MAJOR, 0), 1, "ctfdevice");
  if (err < 0) {
    pr_err("Could not reserve the chardev region: %d\n", err);
    return err;
  }

  cdev_init(&ctf_cdev, &ctf_fops);
  err = cdev_add(&ctf_cdev, MKDEV(CTF_MAJOR, 0), 1);
  if (err < 0) {
    pr_err("Could not initialize the chardev: %d\n", err);
    unregister_chrdev_region(MKDEV(CTF_MAJOR, 0), 1);
    return err;
  }

  pr_info("Ready!\n");

  return 0;
}

module_init(ctf_init_module);

static void __exit ctf_exit_module(void)
{
  pr_info("Exiting...\n");
  cdev_del(&ctf_cdev);
  unregister_chrdev_region(MKDEV(CTF_MAJOR, 0), 1);
}

module_exit(ctf_exit_module);
