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
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"
#include "kernel/fs.h"
#include "kernel/file.h"
#include "user/user.h"
#include "kernel/fcntl.h"

void strncpy(char *dst, char *src, int n) {
    int i;
    for (i = 0; i < n && src[i]; i++) dst[i] = src[i];
    if (i < n) dst[i] = 0;
    else dst[n - 1] = 0;
}

#include "device.h"

// For communication with the device driver in the xv6 kernel.
#ifndef DEV_PCI_MAJOR
#define DEV_PCI_MAJOR 2
#endif

#define MAX_DEVICES 2
#define MAX_ENTRIES_PER_DEVICE 64
#define MAX_PACKAGE_LENGTH 0x100
#define MAX_ENTRY_LENGTH (MAX_PACKAGE_LENGTH - 4)

const static struct DeviceConfigDescriptor DeviceConfig = {
    .device_config_descriptor_length = sizeof(struct DeviceConfigDescriptor),
    .config_version = CONFIG_VERSION,
    .device_version = CONFIG_VERSION,
    .host_config_descriptor_length = sizeof(struct HostConfigDescriptor),
    .max_packet_size = MAX_PACKAGE_LENGTH
};

struct Entry {
    u8 used;
    char key[MAX_ENTRY_LENGTH];
    char value[MAX_ENTRY_LENGTH];
};

struct DeviceState {
    u8 initialized;
    struct HostConfigDescriptor configuration;

    char current_key[MAX_ENTRY_LENGTH];
    struct Entry entries[MAX_ENTRIES_PER_DEVICE];
};

struct DeviceState configuration[MAX_DEVICES] = {};
#define MAX_PAYLOAD_LEN MAX_ENTRY_LENGTH

void debug_dump() {
    printf("debug dump\n");
    for (int idx = 0; idx < MAX_DEVICES; idx++) {
        for (int i = 0; i < MAX_ENTRIES_PER_DEVICE; i++) {
            if (configuration[idx].entries[i].used) {
                printf(" dev %d entry %d: %s:%s\n", 
                    idx, i, configuration[idx].entries[i].key, configuration[idx].entries[i].value);
            }
        }
    }
}

void  __attribute__ ((noinline)) init_machine(int idx) {
    unsigned char *base_addr = (unsigned char*) (0x13370000 + (uint64)idx * 0x1000);
    struct IoBlock *io = (struct IoBlock*) base_addr;
    io->status = STATUS_REQ_INIT;
}

void  __attribute__ ((noinline)) handle_machine(int idx) {
    char buf[MAX_PAYLOAD_LEN] = {};
    unsigned char *base_addr = (unsigned char*) (0x13370000 + (uint64)idx * 0x1000);
    struct IoBlock *io = (struct IoBlock*) base_addr;
    struct DeviceState *device = &configuration[idx];

    if (!(io->cmd & CMD_EXECUTE)) {
        return;
    }

    u8 cmd = io->cmd & ~CMD_EXECUTE;
    io->status = STATUS_IN_PROGRESS;

    if (!device->initialized && cmd != CMD_SET_HOST_CONFIG && cmd != CMD_GET_DEVICE_CONFIG) {
        // Device not initialized. Request sent is not available for uninitialized devices.
        io->length = 0;
        io->status = STATUS_REQ_INIT;
        goto done;
    }

    if (device->initialized && cmd == CMD_SET_HOST_CONFIG) {
        // Device already initialized, we do not want another config!
        io->length = 0;
        io->status = STATUS_ERROR;
        goto done;
    }

    // Package size limit. Length verified when the host config descriptor is set up, so this should
    // be safe (unless someone might have introduced a vuln there) ;)
    int limit = device->configuration.max_packet_size - 4;

    if (device->initialized) {
        // Check length.
        if (io->length > limit) {
            io->length = 0;
            io->status = STATUS_OOM;
            goto done;
        }

        // Copy over payload.
        for (unsigned int i = 0; i < io->length; i++) {
            buf[i] = base_addr[4 + i];
        }
    }

    switch (cmd) {
        case CMD_SET_ENCRYPTION_KEY:
            io->length = 0;
            io->status = STATUS_NOTSUPPORTED;
        break;
        case CMD_GET_KEY:
            // Bug #2 - can be changed by exploiting the firmware and sending more data than the guest expects.
            strncpy((char*)io->iobuf, device->current_key, limit);
            io->length = strlen(device->current_key);
            io->status = STATUS_OK;
        break;
        case CMD_SET_KEY: {
            int n = io->length + 1;  // +1 for nullbyte
            if (n > limit)
                n = limit;

            memset(device->current_key, 0, MAX_ENTRY_LENGTH);
            strncpy(device->current_key, buf, n);
            io->status = STATUS_OK;
        } break;
        case CMD_GET_VAL: {
            struct Entry *e = device->entries;
            for (int i = 0; i < MAX_ENTRIES_PER_DEVICE; i++) {
                if (e[i].used && !strcmp(e[i].key, device->current_key)) {
                    strncpy((char*)io->iobuf, e[i].value, limit);
                    io->status = STATUS_OK;
                    io->length = strlen(e[i].value);
                    goto done;
                }
            }

            io->status = STATUS_NOTFOUND;
        }
        break;
        case CMD_SET_VAL: {
            int n = io->length + 1; // 1 additional for 0 byte
            if (n > limit) n = limit;
            // Check if entry with that name exists
            struct Entry *e = device->entries;
            for (int i = 0; i < MAX_ENTRIES_PER_DEVICE; i++) {
                if (e[i].used && !strcmp(e[i].key, device->current_key)) {
                    memset(e[i].value, 0, MAX_ENTRY_LENGTH);
                    strncpy(e[i].value, buf, n);
                    io->status = STATUS_OK;
                    goto done;
                }
            }

            // Can we create a new one?
            for (int i = 0; i < MAX_ENTRIES_PER_DEVICE; i++) {
                if (!e[i].used) {
                    e[i].used = 1;
                    strncpy(e[i].key, device->current_key, MAX_ENTRY_LENGTH);
                    memset(e[i].value, 0, MAX_ENTRY_LENGTH);
                    strncpy(e[i].value, buf, n);
                    io->status = STATUS_OK;
                    goto done;
                }
            }

            io->status = STATUS_OOM;
        } break;
        case CMD_DELETE: {
            // Check if entry with that name exists
            struct Entry *e = device->entries;
            for (int i = 0; i < MAX_ENTRIES_PER_DEVICE; i++) {
                if (e[i].used && !strcmp(e[i].key, device->current_key)) {
                    e[i].used = 0;
                    io->status = STATUS_OK;
                    goto done;
                }
            }
            io->status = STATUS_ERROR;
        } break;
        case CMD_GET_DEVICE_CONFIG:
            // Publish device configuration to the host.
            *(struct DeviceConfigDescriptor*)io->iobuf = DeviceConfig;
            io->length = sizeof(struct DeviceConfigDescriptor);
            io->status = STATUS_OK;
        break;
        case CMD_SET_HOST_CONFIG: {
            // Get host configuration.
            struct HostConfigDescriptor *hconf = (struct HostConfigDescriptor*)io->iobuf;

            if (hconf->host_config_descriptor_length == sizeof(struct HostConfigDescriptor) &&
                hconf->config_version == CONFIG_VERSION) {
                // Version correct, check length. TOCTOU vulnerability here.
                if (hconf->max_packet_size > MAX_PACKAGE_LENGTH) {
                    printf("Invalid host packet size %d, device maximum %d\n",
                        hconf->max_packet_size, MAX_PACKAGE_LENGTH);
                    io->status = STATUS_OOM;
                } else {
                    printf("Valid host configuration descriptor. Version %d, packet size=%d\n",
                        hconf->config_version, hconf->max_packet_size);

                    // Clear stored memory.
                    for (int i = 0; i < MAX_ENTRIES_PER_DEVICE; i++) {
                        memset(device->entries[i].key, 0, MAX_ENTRY_LENGTH);
                        memset(device->entries[i].value, 0, MAX_ENTRY_LENGTH);
                        device->entries[i].used = 0;
                    }

                    // Clear active key.
                    memset(device->current_key, 0, MAX_ENTRY_LENGTH);

                    device->configuration = *hconf;
                    device->initialized = 1;
                    io->status = STATUS_OK;
                }
            } else {
                io->status = STATUS_ERROR;
            }
        } break;
        default:
            // Received invalid opcode, reinitialize device.
            device->initialized = 0;
            io->status = STATUS_ERROR;
        break;
    }

done:
    // Mark this as done.
    io->cmd &= ~CMD_EXECUTE;

    // Trigger IRQ.
    io->iobuf[0xFFF - 4] = 1;
}

int main(int argc, char *argv[]) {
    int fd = open("pci", O_RDWR);
    if (fd < 0) {
        mknod("pci", DEV_PCI_MAJOR, 0);
        fd = open("pci", O_RDWR);
    }

    // There are no IOCTLs or anything, just read/write.
    int n_devices;
    if (read(fd, &n_devices, sizeof(n_devices)) != sizeof(int)) {
        printf("Reading # of connections failed\n");
        exit(1);
    }

    close(fd);

    if (n_devices < 1 || n_devices > MAX_DEVICES) {
        printf("Invalid # of connections\n");
        exit(2);
    }

    for (int i = 0; i < n_devices; i++)
        init_machine(i);

    printf("Ready\n");
    for(;;) {
        for (int i = 0; i < n_devices; i++)
            handle_machine(i);
    }

    exit(0);
}
