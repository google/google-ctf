#!/usr/bin/env bash

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

set -ex

function cleanup() {
    sudo umount --recursive flag_vm || true
    sudo umount --recursive challenge_vm || true
    rm -rf flag_vm
    rm -rf challenge_vm
}

function initialize() {
    # Create initial VM
    sudo rm -rf challenge_vm
    sudo mkdir -p challenge_vm

    # Create disk (2G)
    dd if=/dev/null of=challenge_vm.img bs=1M seek=2048
    sudo mkfs.ext4 -F challenge_vm.img

    # Mount disk
    sudo mount -t ext4 -o loop challenge_vm.img challenge_vm

    # Install required packages
    sudo debootstrap \
        --arch=amd64 \
        --include=passwd \
         stable \
         ./challenge_vm http://deb.debian.org/debian/
    sudo rm -rf ./challenge_vm/var/lib/apt/lists/*
}

function open_image() {
    sudo rm -rf challenge_vm flag_vm
    sudo mkdir -p challenge_vm flag_vm
    sudo mount -o loop ./challenge_vm.img ./challenge_vm
    sudo mount -o loop ./flag_vm.img ./flag_vm
}

function create_configs() {
    # Set root password
    echo "root:password" | sudo chroot ./challenge_vm /bin/bash -c "PATH=/bin:/sbin chpasswd"

    # Set fstab (mount tmpfs)
    echo "tmpfs /tmp tmpfs nosuid,nodev,noatime 0 0" | sudo tee ./challenge_vm/etc/fstab

    # Enable autologin
    # does not work :/
    #sudo sed -i 's/agetty -o/agetty -a root -o/' ./challenge_vm/lib/systemd/system/getty@.service
}

function copy_vm1() {
    # Challenge VM
    # Set hostname
    echo "vm" | sudo tee ./challenge_vm/etc/hostname

    # Install packages
    EXTRA_PACKETS="build-essential vim linux-headers-4.19.0-16-amd64 linux-image-4.19.0-16-amd64 pciutils"
    sudo chroot ./challenge_vm /bin/bash -c "export PATH=/bin:/sbin; apt update; DEBIAN_FRONTEND=noninteractive apt install -y $EXTRA_PACKETS"
    sudo chroot ./challenge_vm /bin/bash -c "PATH=/bin:/sbin rm -rf ./challenge_vm/var/lib/apt/lists/*";
    sudo rm -f ./challenge_vm/root/.bash_history

    # Install setkey example.
    sudo cp ../guest-utils/set_key.c ./challenge_vm/root

    # We provide the driver source, so provide it.
    sudo mkdir -p ./challenge_vm/root/driver
    sudo cp -r --dereference -v ../guest-driver/* ./challenge_vm/root/driver

    # Also build it here.
    build_kernel_driver ./challenge_vm
}

function copy_vm2() {
    # Set hostname
    echo "flag-vm" | sudo tee ./flag_vm/etc/hostname

    # Create systemd service
    sudo install -m 644 ./flag-vm.service ./flag_vm/etc/systemd/system/flag-vm.service
    sudo install -m 755 ./flag_inserter.sh ./flag_vm/root/flag_inserter.sh

    # Activate systemd service
    sudo chroot ./flag_vm /bin/bash -c "PATH=/bin:/sbin systemctl enable flag-vm.service"

    # Copy over flag placer service
    gcc -static -O2 -Wall ../guest-utils/flag_placer.c -o out/flag_placer
    sudo install -m 750 out/flag_placer ./flag_vm/root

    # Installs the kernel driver
    # Only needed for the flag vm as it does not contain the driver source nor
    # does it contain the build toolchain.
    sudo install ./out/main.ko ./flag_vm/root/main.ko

    #echo "Manual introspection time ;)"
    #sudo chroot ./flag_vm /bin/bash -c "PATH=/bin:/sbin exec /bin/bash"

}

function build_kernel_driver() {
    sudo chroot $1 /bin/bash -c "export PATH=/bin:/sbin; cd /root/driver; make KERNEL_VERSION=4.19.0-16-amd64 clean; make KERNEL_VERSION=4.19.0-16-amd64; cp *.ko /root/main.ko"
    # Extract driver
    sudo cp $1/root/driver/main.ko out/main.ko
    sudo chown chief out/main.ko
}

trap cleanup EXIT
# Make sure everything is not mounted first.
sudo umount --recursive challenge_vm || true
sudo umount --recursive flag_vm || true

# Create challenge image
if [ "x$1" == "xinit" ]; then
    echo "Initializing new image"
    rm -f challenge_vm.qcow2 flag_vm.qcow2
    initialize
    create_configs

    sudo umount --recursive challenge_vm
    cp challenge_vm.img flag_vm.img
else
    echo "Reusing existing image"
fi

sudo rm -rf out
mkdir -p out

open_image

# Copy challenge-vm specific stuff
copy_vm1

# Copy flag-vm specific stuff
# Also builds the kernel module and puts it into cwd
copy_vm2

# Firmware will be given to the user

# Copying back kernel + initrd
cp ./challenge_vm/boot/vmlinuz* out/vmlinuz
cp ./challenge_vm/boot/initrd* out/initrd.img

# Unmount folders that might've been mounted.
sudo umount --recursive challenge_vm
sudo umount --recursive flag_vm
rm -rf flag_vm
rm -rf challenge_vm

trap '' EXIT

# Convert image to qcow2 format
qemu-img convert challenge_vm.img -O qcow2 out/challenge_vm.qcow2
qemu-img convert flag_vm.img -O qcow2 out/flag_vm.qcow2
