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
#include <linux/errno.h>
#include <linux/init.h>
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

#include "chck_dev.h"

static int chck_device_add(struct acpi_device *device);
static int chck_device_remove(struct acpi_device *device);

static const struct acpi_device_id chck_device_ids[] = {
  { "CHCK0001", 0 },
  { "", 0 },
};
MODULE_DEVICE_TABLE(acpi, chck_device_ids);

static struct acpi_driver chck_driver = {
  .name = "Chck",
  .class = "Chck",
  .ids = chck_device_ids,
  .ops = {
    .add = chck_device_add,
    .remove = chck_device_remove,
  },
  .owner = THIS_MODULE,
};

static int __init chck_init(void)
{
  int result  = 0;
  result = acpi_bus_register_driver(&chck_driver);
  if (result < 0) {
    ACPI_DEBUG_PRINT((ACPI_DB_ERROR,
                      "Error registering driver\n"));
    return -ENODEV;
  }

  return 0;
}

static void __exit chck_exit(void)
{
  acpi_bus_unregister_driver(&chck_driver);
}

static int chck_device_add(struct acpi_device *device) {
  return create_chck(device->handle);
}

static int chck_device_remove(struct acpi_device *device) {  
  destroy_chck();
  return 0;
}

module_init(chck_init);
module_exit(chck_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Connor Wood <venos@google.com>");
