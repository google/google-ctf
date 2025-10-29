#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex -o pipefail

cd /build/rustc_codegen_gcc
# Avoid having to redownload dependencies every time
export CARGO_HOME="/src/.cargo_home"
export CARGO_TARGET_DIR="/src/target.docker"
./y.sh cargo build --release --target $(pwd)/target_specs/m68k-unknown-linux-gnu.json --manifest-path /src/rom/Cargo.toml --lib \
    -Zbuild-std="core,alloc" -Zbuild-std-features="compiler_builtins/no-f16-f128"

cd /src/rom

m68k-elf-gcc -mcpu=68000 \
    -T /src/megadrive.x \
    -O2 -nostartfiles -nostdlib -static -nolibc \
    -Wl,-gc-sections -flto -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -fno-exceptions \
    entry.S hack.c /src/target.docker/m68k-unknown-linux-gnu/release/librom.a \
    -o /tmp/out.elf -lgcc

cp /tmp/out.elf /src/sonk.elf
m68k-elf-objcopy -O binary /tmp/out.elf /src/sonk.md
