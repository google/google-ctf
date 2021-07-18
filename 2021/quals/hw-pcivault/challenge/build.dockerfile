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

# Since we need to provide the firmware as an attachment we need to build it
# here.
FROM ubuntu:21.04 as build

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    build-essential \
    curl \
    git \
    python \
    socat \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev bzip2 ninja-build python3 \
    gcc-riscv64-unknown-elf \
 && rm -rf /var/lib/apt/lists/*

# Build qemu with vfio-user support
RUN git clone https://github.com/oracle/qemu.git --branch vfio-user-v0.9
RUN cd qemu \
    && ./configure --target-list=x86_64-softmmu \
    && make -j $(nproc)

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    cargo libjson-c-dev libcmocka-dev libssl-dev cmake \
 && rm -rf /var/lib/apt/lists/*

# Prepare vfio-user
RUN git clone https://github.com/nutanix/libvfio-user.git
RUN cd libvfio-user \
    && make -j $(nproc)
# make BUILD_TYPE=rel

# Copy over vfio-user-sys
COPY libvfio-user-sys libvfio-user-sys
COPY emulator emulator

# Build riscv-rust
RUN git clone https://github.com/takahirox/riscv-rust.git && \
    cd riscv-rust && \
    git checkout b4895fc56b16815d622b088d188ac65d640d25ab
# + patch
COPY riscv-rust.patch riscv-rust.patch
RUN cd riscv-rust && \
   patch -p1 < ../riscv-rust.patch

# Build firmware
# Copy sources
COPY firmware firmware
COPY common common
RUN git clone https://github.com/mit-pdos/xv6-riscv.git && \
    cd xv6-riscv && \
    git checkout 077323a8f0b3440fcc3d082096a2d83fe5461d70
# Apply patch
COPY xv6-riscv.patch xv6-riscv.patch

RUN cd xv6-riscv && \
    patch -p1 < ../xv6-riscv.patch && \
    make TOOLPREFIX=riscv64-unknown-elf- && \
    make TOOLPREFIX=riscv64-unknown-elf- fs.img

RUN cd emulator && \
    KERNEL_IMG=/xv6-riscv/kernel/kernel FS_IMG=/xv6-riscv/fs.img cargo build --release

