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

all: upload_player_image

upload_player_image: player-image.tar.gz
	HASH="$$(sha512sum player-image.tar.gz | awk '{print $$1}')"; \
	gsutil cp player-image.tar.gz "gs://gctf-2021-attachments-project/$${HASH}"; \
	sed -i -e "s/HASH=[0-9a-f]*/HASH=$${HASH}/" run_local.sh

#player-image.tar.gz: upload_build_tar
player-image.tar.gz:
	- docker rm pcivault-player-image 2>/dev/null
	docker build -t pcivault-player-image -f player-image.dockerfile .
	docker save pcivault-player-image -o player-image.tar
	gzip player-image.tar
	- docker rm pcivault-player-image 2>/dev/null

upload_build_tar: build.tar.gz
	HASH="$$(sha512sum build.tar.gz | awk '{print $$1}')"; \
	gsutil cp build.tar.gz "gs://gctf-2021-attachments-project/$${HASH}"; \
	sed -i -e "s/ENV HASH=[0-9a-f]*/ENV HASH=$${HASH}/" player-image.dockerfile; \
	sed -i -e "s/ENV HASH=[0-9a-f]*/ENV HASH=$${HASH}/" Dockerfile

build.tar.gz: disk kernel
	- rm build.tar.gz
	tar -czvf build.tar.gz guest-image/out build

# This generates guest-image/out/* (4 files actually)
disk:
	# Create initial image
	bash -c 'cd guest-image && ./create_vm.sh init'

kernel: build.dockerfile firmware/firmware.c xv6-riscv.patch
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/xv6-riscv/fs.img build/
	docker cp tmp-chal-container:/xv6-riscv/kernel/kernel build/
	docker cp tmp-chal-container:/xv6-riscv/_firmware build/firmware.elf
	docker cp tmp-chal-container:/qemu/build/qemu-system-x86_64 build/qemu-system-x86_64
	docker cp tmp-chal-container:/qemu/pc-bios/ build/pc-bios
	docker cp tmp-chal-container:/emulator/target/release/emulator build/emulator
	docker cp tmp-chal-container:/libvfio-user/build/dbg/lib/libvfio-user.so.0.0.1 build/
	docker cp tmp-chal-container:/libvfio-user/build/dbg/lib/libvfio-user.so.0 build/
	docker cp tmp-chal-container:/libvfio-user/build/dbg/lib/libvfio-user.so build/
	- docker rm tmp-chal-container 2>/dev/null

fs.img: kernel
firmware.elf: kernel

