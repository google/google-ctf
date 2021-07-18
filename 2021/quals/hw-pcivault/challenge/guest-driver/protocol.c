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
#include "protocol.h"

#include <linux/wait.h>

#define EXEC_SYNC(priv, cmd)                                   \
  do {                                                         \
    iowrite8((cmd) | CMD_EXECUTE, (priv)->hwmem);              \
    wait_event(device_wait_queue,                              \
               ((ioread8((priv)->hwmem) & CMD_EXECUTE) == 0)); \
  } while (0)

int device_status_to_error_code(u8 status_code) {
  switch (status_code) {
    case STATUS_OK:
      return 0;
    case STATUS_IN_PROGRESS:
      return -EINPROGRESS;
    case STATUS_REQ_INIT:
      // Next call should init the device anyway.
      return -EAGAIN;
    case STATUS_ERROR:
      return -EIO;
    case STATUS_OOM:
      return -ENOMEM;
    default:
      return -EIO;
  }
}

int device_init(struct private_data *priv) {
  struct DeviceConfigDescriptor device_descriptor = {};
  struct HostConfigDescriptor host_descriptor = {
      .host_config_descriptor_length = sizeof(struct HostConfigDescriptor),
      .config_version = CONFIG_VERSION,
      .max_packet_size = MAX_PACKET_SIZE};
  u16 len;
  u8 status;
  int i;

  printk(KERN_INFO "Initializing device\n");
  status = ioread8(priv->hwmem + 1);
  if (status != STATUS_REQ_INIT) {
    printk(KERN_INFO "Device already initialized, skipping\n");
    return 0;
  }

  // 1) Get device descriptor.
  EXEC_SYNC(priv, CMD_GET_DEVICE_CONFIG);
  status = ioread8(priv->hwmem + 1);
  len = ioread16(priv->hwmem + 2);

  if (status != STATUS_OK) {
    printk(KERN_INFO "Device did not accept GetDeviceConfig request: %d\n",
           status);
    return device_status_to_error_code(status);
  }

  if (len != sizeof(struct DeviceConfigDescriptor)) {
    printk(KERN_INFO
           "Device sent response of invalid length (%d vs expected %ld)\n",
           len, sizeof(struct DeviceConfigDescriptor));
    return -EPROTO;
  }

  for (i = 0; i < sizeof(struct DeviceConfigDescriptor); i++) {
    ((u8 *)&device_descriptor)[i] = ioread8(priv->hwmem + 4 + i);
  }

  if (device_descriptor.device_config_descriptor_length !=
          sizeof(struct DeviceConfigDescriptor) ||
      device_descriptor.config_version != CONFIG_VERSION ||
      device_descriptor.device_version != 1) {
    printk(KERN_INFO "Unknown version details in the device descriptor\n");
    return -EPROTO;
  }

  priv->device_max_packet_size = device_descriptor.max_packet_size;

  // 2) Send host descriptor.
  for (i = 0; i < device_descriptor.host_config_descriptor_length; i++) {
    iowrite8(((u8 *)&host_descriptor)[i], priv->hwmem + 4 + i);
  }

  iowrite8(device_descriptor.host_config_descriptor_length, priv->hwmem + 2);
  EXEC_SYNC(priv, CMD_SET_HOST_CONFIG);
  status = ioread8(priv->hwmem + 1);
  if (status != STATUS_OK) {
    printk(KERN_INFO "Sending host config failed: %d\n", status);
    return device_status_to_error_code(status);
  }

  printk(KERN_INFO "Device initialized\n");
  return 0;
}

int device_select_entry(struct private_data *priv, const char *entry_name) {
  u16 len = 0;
  int rc;

  // Assure device is initialized.
  if (ioread8(priv->hwmem + 1) == STATUS_REQ_INIT) {
    rc = device_init(priv);
    if (rc < 0) return rc;
  }

  // Write payload.
  for (len = 0; entry_name[len] && len < priv->device_max_packet_size - 4;
       len++) {
    iowrite8(entry_name[len], priv->hwmem + 4 + len);
  }

  // Write entry length.
  iowrite16(len, priv->hwmem + 2);

  EXEC_SYNC(priv, CMD_SET_KEY);
  return device_status_to_error_code(ioread8(priv->hwmem + 1));
}

int device_read_entry(struct private_data *priv, char *buffer) {
  size_t i;
  u8 status;
  u16 len;
  int rc;

  // Assure device is initialized.
  if (ioread8(priv->hwmem + 1) == STATUS_REQ_INIT) {
    rc = device_init(priv);
    if (rc < 0) return rc;
  }

  EXEC_SYNC(priv, CMD_GET_VAL);

  status = ioread8(priv->hwmem + 1);
  len = ioread16(priv->hwmem + 2);

  for (i = 0; i < len; i++) {
    buffer[i] = ioread8(priv->hwmem + 4 + i);
  }

  if (status != STATUS_OK) return device_status_to_error_code(status);
  return len;
}

int device_write_entry(struct private_data *priv, const char *buffer,
                       size_t buffer_sz) {
  size_t i;
  int rc;

  // Assure device is initialized.
  if (ioread8(priv->hwmem + 1) == STATUS_REQ_INIT) {
    rc = device_init(priv);
    if (rc < 0) return rc;
  }

  if (buffer == NULL) {
    return -EINVAL;
  }

  if (buffer_sz > priv->device_max_packet_size - 4) {
    return -EOVERFLOW;
  }

  for (i = 0; i < buffer_sz; i++) {
    iowrite8(buffer[i], priv->hwmem + 4 + i);
  }

  // Write length
  iowrite16(buffer_sz, priv->hwmem + 2);

  EXEC_SYNC(priv, CMD_SET_VAL);

  return device_status_to_error_code(ioread8(priv->hwmem + 1));
}

int device_delete_entry(struct private_data *priv) {
  int rc;

  // Assure device is initialized.
  if (ioread8(priv->hwmem + 1) == STATUS_REQ_INIT) {
    rc = device_init(priv);
    if (rc < 0) return rc;
  }

  EXEC_SYNC(priv, CMD_DELETE);
  return device_status_to_error_code(ioread8(priv->hwmem + 1));
}

int device_set_encryption_key(struct private_data *priv) {
  int rc;
  int i;

  // Assure device is initialized.
  if (ioread8(priv->hwmem + 1) == STATUS_REQ_INIT) {
    rc = device_init(priv);
    if (rc < 0) return rc;
  }

  for (i = 0; i < sizeof(priv->encryption_key) && i < priv->device_max_packet_size - 4;
       i++) {
    iowrite8(priv->encryption_key[i], priv->hwmem + 4 + i);
  }

  // Write entry length.
  iowrite16(i, priv->hwmem + 2);

  EXEC_SYNC(priv, CMD_SET_ENCRYPTION_KEY);
  return device_status_to_error_code(ioread8(priv->hwmem + 1));
}
