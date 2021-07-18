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
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <linux/mutex.h>
#include <linux/pci.h>

#include "device.h"

#define MAX_PACKET_SIZE 0x100

extern wait_queue_head_t device_wait_queue;

struct private_data {
  u8 __iomem *hwmem;
  u16 device_max_packet_size;
  char encryption_key[64];
};

int device_init(struct private_data *priv);
int device_do_nop(struct private_data *priv, u32 payload);
int device_select_entry(struct private_data *priv, const char *entry_name);
int device_read_entry(struct private_data *priv, char *buffer);
int device_write_entry(struct private_data *priv, const char *buffer,
                       size_t buffer_sz);
int device_delete_entry(struct private_data *priv);
int device_set_encryption_key(struct private_data *priv);

#endif
