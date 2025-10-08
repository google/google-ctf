#!/bin/bash
set -ex -o pipefail

cd /build/rustc_codegen_gcc
# Avoid having to redownload dependencies every time
export CARGO_HOME="/src/.cargo_home"
export CARGO_TARGET_DIR="/src/target.docker"
./y.sh cargo build --release --target $(pwd)/target_specs/m68k-unknown-linux-gnu.json --manifest-path /src/rom/Cargo.toml --lib \
    -Zbuild-std="core,alloc" -Zbuild-std-features="compiler_builtins/no-f16-f128"

cd /src/rom

m68k-elf-objcopy -I binary -O elf32-m68k ../game/src/res/paintdata /tmp/paintdata.o --rename-section=".data=.paintdata"
m68k-elf-gcc -mcpu=68000 \
    -T /src/megadrive.x \
    -O2 -nostartfiles -nostdlib -static -nolibc \
    -Wl,-gc-sections -flto -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -fno-exceptions \
    entry.S hack.c /tmp/paintdata.o /src/target.docker/m68k-unknown-linux-gnu/release/librom.a \
    -o /tmp/out.elf -lgcc

cp /tmp/out.elf /src/hx8.elf
m68k-elf-objcopy -O binary -j .text -j .data -j .rodata -j .paintdata /tmp/out.elf /src/hx8.md
