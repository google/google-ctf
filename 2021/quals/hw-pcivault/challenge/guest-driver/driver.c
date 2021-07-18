// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uaccess.h>

#include "protocol.h"

#define DRIVER_NAME "PCIVault driver"

wait_queue_head_t device_wait_queue;

DEFINE_MUTEX(mutex);

static struct pci_dev *g_pci_dev = NULL;
static struct pci_device_id driver_id_table[] = {{PCI_DEVICE(0x1337, 0xCAFE)},
                                                 {
                                                     0,
                                                 }};

MODULE_DEVICE_TABLE(pci, driver_id_table);

static int do_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void do_remove(struct pci_dev *pdev);

static struct pci_driver pcivault_driver = {.name = DRIVER_NAME,
                                            .id_table = driver_id_table,
                                            .probe = do_probe,
                                            .remove = do_remove};

// Char stuff
static int cdev_major = 0;
static long cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static ssize_t cdev_read(struct file *file, char *buf, size_t length,
                         loff_t *off);
static ssize_t cdev_write(struct file *file, const char *buf, size_t length,
                          loff_t *off);

struct file_operations cdev_fops = {
    .unlocked_ioctl = cdev_ioctl, .read = cdev_read, .write = cdev_write};

static int __init pcivault_init(void) {
  int rc;
  mutex_init(&mutex);
  init_waitqueue_head(&device_wait_queue);
  rc = pci_register_driver(&pcivault_driver);
  if (rc < 0) return rc;

  cdev_major = register_chrdev(0, "pcivault", &cdev_fops);
  if (cdev_major < 0) return cdev_major;
  printk(KERN_INFO "Got major %d (mknod /dev/pcivault c %d 0)\n", cdev_major,
         cdev_major);
  return 0;
}

static void __exit pcivault_exit(void) {
  pci_unregister_driver(&pcivault_driver);
  unregister_chrdev(cdev_major, "pcivault");
}

static irqreturn_t irq_handler(int irq, void *cookie) {
  wake_up(&device_wait_queue);
  return IRQ_HANDLED;
}

// Requires the mutex to be held already.
static int set_encryption_key(void) {
  if (g_pci_dev != NULL) {
    printk(KERN_INFO "Setting device encryption key\n");
    return device_set_encryption_key(pci_get_drvdata(g_pci_dev));
  }
  return 0;
}

static int do_probe(struct pci_dev *pdev, const struct pci_device_id *ent) {
  int bar, rc;
  u16 vendor, device;
  unsigned long mmio_start, mmio_len;
  struct private_data *drv_priv;

  // We can only handle one device.
  mutex_lock(&mutex);
  if (g_pci_dev != NULL) {
    mutex_unlock(&mutex);
    return -EBUSY;
  }

  pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
  pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
  bar = pci_select_bars(pdev, IORESOURCE_MEM);

  rc = pci_enable_device_mem(pdev);
  if (rc) {
    printk(KERN_INFO "pci_enable_device_mem failed\n");
    goto err_disable;
  }

  rc = pci_request_region(pdev, bar, DRIVER_NAME);
  if (rc) {
    printk(KERN_INFO "pci_request_region_mem failed\n");
    goto err_disable;
  }

  // Allocate device memory
  mmio_start = pci_resource_start(pdev, 2);
  mmio_len = pci_resource_len(pdev, 2);
  drv_priv = kzalloc(sizeof(struct private_data), GFP_KERNEL);

  if (!drv_priv) {
    rc = -ENOMEM;
    goto err_release_region;
  }

  drv_priv->hwmem = pci_iomap(pdev, 2, mmio_len);
  if (!drv_priv->hwmem) {
    printk(KERN_INFO "ioremap failed (mmio_start=%lX mmio_len=%lX)\n", mmio_start,
           mmio_len);
    rc = -EIO;
    goto err_release_region;
  }

  pci_set_drvdata(pdev, drv_priv);

  rc = request_irq(pdev->irq, irq_handler, 0, DRIVER_NAME, NULL);
  if (rc < 0) {
    goto err_release_region;
  }

  // Initialize the device
  rc = device_init(drv_priv);
  if (rc < 0) {
    goto err_irq;
  }

  g_pci_dev = pdev;
  mutex_unlock(&mutex);
  return 0;

err_irq:
  free_irq(pdev->irq, NULL);
err_release_region:
  pci_release_region(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
err_disable:
  pci_disable_device(pdev);
  mutex_unlock(&mutex);
  return rc;
}

static void do_remove(struct pci_dev *pdev) {
  struct private_data *drv_priv = pci_get_drvdata(pdev);

  mutex_lock(&mutex);
  if (pdev == g_pci_dev) {
    g_pci_dev = NULL;
  }
  mutex_unlock(&mutex);

  if (drv_priv) {
    if (drv_priv->hwmem) {
      iounmap(drv_priv->hwmem);
    }
    kfree(drv_priv);
  }

  free_irq(pdev->irq, NULL);
  pci_release_region(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
  pci_disable_device(pdev);
}

static long cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  int rc = 0;
  char buf[MAX_PACKET_SIZE];
  char *usr_buf = (char *)arg;

  switch (cmd) {
    case 0: {
      struct private_data *priv;
      if (!usr_buf) return -EINVAL;
      mutex_lock(&mutex);
      if (g_pci_dev == NULL) {
        mutex_unlock(&mutex);
        return -EIO;
      }

      priv = (struct private_data *)pci_get_drvdata(g_pci_dev);
      if (copy_from_user(priv->encryption_key, usr_buf,
                         sizeof(priv->encryption_key))) {
        mutex_unlock(&mutex);
        return -EINVAL;
      }
      // Encryption WIP.
      // TODO: Switch to guest side encryption
      mutex_unlock(&mutex);

      return rc;
    }
    case 1:
      // select
      if (!usr_buf) return -EINVAL;
      if (copy_from_user(buf, usr_buf, sizeof(buf))) return -EINVAL;
      mutex_lock(&mutex);
      if (g_pci_dev == NULL) {
        mutex_unlock(&mutex);
        return -EIO;
      }
      rc = device_select_entry(
          (struct private_data *)pci_get_drvdata(g_pci_dev), buf);
      mutex_unlock(&mutex);
      return rc;
    case 4:
      // delete
      mutex_lock(&mutex);
      if (g_pci_dev == NULL) {
        mutex_unlock(&mutex);
        return -EIO;
      }
      rc = device_delete_entry(
          (struct private_data *)pci_get_drvdata(g_pci_dev));
      mutex_unlock(&mutex);
      return rc;

    case 5:
      mutex_lock(&mutex);
      rc = set_encryption_key();
      mutex_unlock(&mutex);
      if (rc) {
        printk(KERN_INFO "Setting device encryption key failed, rc=%d\n", rc);
      }
      return rc;


    default:
      return -EINVAL;
  }
}
static ssize_t cdev_read(struct file *file, char *buf, size_t length,
                         loff_t *off) {
  char kbuf[MAX_PACKET_SIZE];
  int rc;

  mutex_lock(&mutex);
  if (g_pci_dev == NULL) {
    mutex_unlock(&mutex);
    return -EIO;
  }
  rc = device_read_entry(pci_get_drvdata(g_pci_dev), kbuf);
  mutex_unlock(&mutex);
  if (rc < 0) return -EIO;
  if (rc > length) rc = length;

  // TODO: Perform decryption

  if (copy_to_user(buf, kbuf, rc)) return -ENOBUFS;
  return rc;
}

static ssize_t cdev_write(struct file *file, const char *buf, size_t length,
                          loff_t *off) {
  char kbuf[MAX_PACKET_SIZE];
  size_t actual_length = length;
  int rc;

  if (*off != 0) return -EINVAL;
  if (actual_length > sizeof(kbuf)) actual_length = sizeof(kbuf);
  if (copy_from_user(kbuf, buf, actual_length)) return -EINVAL;

  // TODO: Perform encryption

  mutex_lock(&mutex);
  if (g_pci_dev == NULL) {
    mutex_unlock(&mutex);
    return -EIO;
  }
  rc = device_write_entry(pci_get_drvdata(g_pci_dev), kbuf, actual_length);
  mutex_unlock(&mutex);
  if (rc < 0) return rc;

  return actual_length;
}

MODULE_LICENSE("Apache");
MODULE_AUTHOR("Kevin Hamacher");
MODULE_DESCRIPTION("PCIVault driver");
MODULE_VERSION("1.0");

module_init(pcivault_init);
module_exit(pcivault_exit);
