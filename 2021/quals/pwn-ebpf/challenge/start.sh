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
  -m 512M \
  -kernel /home/user/bzImage \
  -initrd /home/user/root.cpio.gz \
  -nographic \
  -append "root=/dev/ram rw console=ttyS0 quiet" \
  -cpu 'qemu64,+smep,+smap' \
  -s \
  -monitor none
