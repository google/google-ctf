#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Requires packages: attr ntfs-3g

DISK_IMAGE=p3e.ntfs
DISK_NAME=Family
MOUNT_POINT=/mnt/p3e
CREDENTIALS_FILE=${MOUNT_POINT}/Users/Family/Documents/credentials.txt

# Create a 25 MiB file
dd if=/dev/zero of="${DISK_IMAGE}" iflag=fullblock bs=1MiB count=25
sync

# Mount the file as a loopback device
device=$(sudo losetup --show --find "${DISK_IMAGE}")

# Format the file as ntfs with compression
sudo mkntfs -f -C -L "${DISK_NAME}" "${device}"

# Unmount the file from the loopback device
sudo losetup -d "${device}"

# Mount the file under a directory
sudo mkdir -p "${MOUNT_POINT}"
sudo mount -t ntfs -o stream_interfaces=windows "${DISK_IMAGE}" "${MOUNT_POINT}"

# Fill the disk image with fake files / folders
while read file; do
  folder=$(dirname "${file}")
  mkdir -p "${MOUNT_POINT}/${folder}"
  touch "${MOUNT_POINT}/${file}"
done < fake_files

# Copy the credentials file to the image
cat credentials > "${CREDENTIALS_FILE}"

# Copy the flags as attributes on the credentials file
for stream in "$@"
do
  setfattr -n "user.${stream}" -v "0s$(base64 flag_${stream}.png)" "${CREDENTIALS_FILE}"
done

# Unmount the disk image
sudo umount "${MOUNT_POINT}"
