// Copyright 2020 Google LLC
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/types.h>

#include <linux/acpi.h>
#include <acpi/platform/acenv.h>
#include <acpi/platform/aclinux.h>
#include <acpi/actypes.h>
#include <acpi/acrestyp.h>
#include <acpi/acpixf.h>
#include <acpi/acpi_bus.h>
#include <acpi/acpi_drivers.h>
#include <acpi/acexcep.h>

static const char chck_name[] = "chck";

static int chck_major = 0;
static const int base_minor = 0;
static const int n_minor = 1;

static struct class *chck_class = NULL;
static struct cdev chck_cdev;

static acpi_handle chck_handle;

static ssize_t chck_read(
    struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
  unsigned long long output;
  acpi_status status;

  char buffer[2];

  status = acpi_evaluate_integer(chck_handle, "CHCK",
                                 NULL, &output);
  if (ACPI_FAILURE(status)) {
    printk(KERN_WARNING "Chck: cannot read from method CHCK");
    return -1;
  }

  snprintf(buffer, 2, "%llu", output); // output should never be anything other than 0 or 1
  return simple_read_from_buffer(buf, count, ppos, buffer, 2);
}

static const struct file_operations chck_fops = {
  .read = chck_read,
};

int create_chck(acpi_handle handle) {
  int result;
  dev_t dev = 0;
  struct device *device = NULL;

  result = alloc_chrdev_region(&dev, base_minor, n_minor, chck_name);
  if (result < 0) {
    printk(KERN_WARNING "Chck: cannot register character device region. Error %i", result);
    return result;
  }

  chck_major = MAJOR(dev);

  chck_class = class_create(THIS_MODULE, chck_name);
  if (IS_ERR(chck_class)) {
    result = PTR_ERR(chck_class);
    printk(KERN_WARNING "Chck: cannot register device class. Error %i", result);
    
    unregister_chrdev_region(MKDEV(chck_major, base_minor), n_minor);
    
    return result;
  }

  cdev_init(&chck_cdev, &chck_fops);
  result = cdev_add(&chck_cdev, dev, 1);
  if (result) {
    printk(KERN_WARNING "Chck: cannot register cdev. Error %i", result);

    class_destroy(chck_class);
    unregister_chrdev_region(MKDEV(chck_major, base_minor), n_minor);
    
    return result;
  }

  device = device_create(chck_class, NULL,
                         dev, NULL,
                         chck_name);
  if (IS_ERR(device)) {
    result = PTR_ERR(chck_class);
    printk(KERN_WARNING "Chck: cannot create device. Error %i", result);

    cdev_del(&chck_cdev);
    class_destroy(chck_class);
    unregister_chrdev_region(MKDEV(chck_major, base_minor), n_minor);

    return result;
  }

  chck_handle = handle;

  return 0;
}

void destroy_chck(void) {
  device_destroy(chck_class, MKDEV(chck_major, base_minor));
  cdev_del(&chck_cdev);
  class_destroy(chck_class);
  unregister_chrdev_region(MKDEV(chck_major, base_minor), n_minor);
}
