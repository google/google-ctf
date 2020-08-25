#!/bin/sh
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

qemu-system-x86_64 \
	-nographic \
	-cpu qemu64,+pku,+xsave -m 512 \
	-nic user,id=net,ipv4=on,ipv6=off,restrict=on,hostfwd=tcp:0.0.0.0:1337-10.0.2.1:1234,model=virtio-net-pci \
	-object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
	-kernel bzImage \
	-initrd initramfs.SECRET.cpio.gz \
	-append "console=ttyS0 ip=10.0.2.1::10.0.2.2:255.255.255.0"

