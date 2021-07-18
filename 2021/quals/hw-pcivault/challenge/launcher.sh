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

set -m
function run_vm() {
    qemu-img create -f qcow2 -b /app/$1.qcow2 /tmp/$1.snapshot.qcow2 > /dev/null 2> /dev/null
    ./qemu-system-x86_64 \
            -nodefaults \
            -L /app/qemu/ \
            -enable-kvm \
            -smp 1 \
            -mem-prealloc -m 512 \
            -nographic \
            -kernel /app/vmlinuz \
            -initrd /app/initrd.img \
            -append "console=ttyS0 root=/dev/sda rw panic=-1 panic_on_oops=1" \
            -drive file=/tmp/$1.snapshot.qcow2,media=disk,index=0,werror=ignore,rerror=ignore \
            -device vfio-user-pci,socket=/tmp/device$2.sock \
            -no-reboot \
            $3 > /dev/null 2> /dev/null &
}

cd /app
LD_LIBRARY_PATH=. ./emulator >/dev/null 2>/dev/null &

echo "Starting challenge VM"
run_vm challenge_vm 1 "-serial telnet:127.0.0.1:1338,server"

if [[ -f /app/flag_vm.qcow2 ]]; then
    echo "Starting flag VM"
    run_vm flag_vm 2 "-serial telnet:127.0.0.1:1339,server,nowait"
else
    echo "Skipping flag VM: Image not present"
fi

echo "Forwarding in 3s"
sleep 3
socat - TCP4:127.0.0.1:1338

# Kill VMs
kill -9 0
