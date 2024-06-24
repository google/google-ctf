#!/bin/bash
#
# Copyright 2024 Google LLC
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

CID=0
while [ "$CID" -lt 3 ]; do
  CID=$SRANDOM
done
qemu-system-x86_64 \
  -m 8G \
  -enable-kvm \
  -cpu host \
  -kernel ./bzImage \
  -no-reboot \
  -device vhost-vsock-pci,guest-cid=${CID} \
  -drive file=./rootfs.img,format=raw,if=virtio,readonly=on \
  -append "console=ttyS0 root=/dev/vda systemd.unit=chal.target panic=1" \
  -nographic </dev/null  >&2 >/dev/null &

# Redirect the input to the VM
socat stdio vsock-connect:${CID}:9000,retry=20,interval=0.2
