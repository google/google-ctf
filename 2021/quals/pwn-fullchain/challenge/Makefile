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

# Please use docker for building your challenges so that SREs can rebuild it
# if necessary without installing any dependencies.

all: rootfs.img bzImage ctf.ko

bzImage ctf.ko: kernel_module/ctf.c kernel_module/Kbuild build_kernel.dockerfile kernel.config
	- docker rm tmp-chal-kernel-container 2> /dev/null
	docker build -t tmp-chal-kernel-image -f build_kernel.dockerfile .
	docker run --name tmp-chal-kernel-container tmp-chal-kernel-image /bin/true
	docker cp tmp-chal-kernel-container:/build/linux/arch/x86/boot/bzImage .
	docker cp tmp-chal-kernel-container:/build/kernel_module/ctf.ko .
	- docker rm tmp-chal-kernel-container 2>/dev/null
	touch bzImage ctf.ko

rootfs.img: build_vm.dockerfile chromium/chrome run_chromium.py init ctf.ko
	- docker rm tmp-chal-vm-container 2>/dev/null
	- mkdir rootfs
	# Build the root filesystem of the VM as a container image,
	# then export the contents and put them in an ext4 disk
	docker build -t tmp-chal-vm-image -f build_vm.dockerfile .
	docker create --name tmp-chal-vm-container tmp-chal-vm-image
	docker export tmp-chal-vm-container > rootfs.tar
	- docker rm tmp-chal-container 2>/dev/null
	dd if=/dev/zero of=rootfs.img bs=1G count=3
	sudo mkfs.ext4 -F rootfs.img
	sudo mount -o loop rootfs.img rootfs/
	sudo tar -xf rootfs.tar -C rootfs/
	- rm rootfs.tar
	sudo umount rootfs/

chromium/chrome: .FORCE
	./download_files_from_gcs.sh

.PHONY: .FORCE
.FORCE:
