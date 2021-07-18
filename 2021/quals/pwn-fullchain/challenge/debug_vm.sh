#!/bin/bash
# Copyright 2021 Google LLC
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

qemu-system-x86_64 \
  -smp 2 \
  -nographic \
  -monitor none \
  -m 256M \
  -cpu qemu64,+smep,+smap \
  -no-reboot \
  -kernel ./bzImage \
  -drive file=./rootfs.img,format=raw,if=virtio,readonly \
  -drive file=./flag,format=raw,if=virtio,readonly \
  -virtfs "local,readonly,mount_tag=exploit,security_model=none,path=/tmp/asdf" \
  -append "console=ttyS0 kaslr kpti=1 root=/dev/vda init=/init panic=1 quiet"
