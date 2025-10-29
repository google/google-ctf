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

FROM ubuntu:22.04 AS builder

RUN apt-get -y update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential sudo python3 file \
    flex libmpfr-dev libgmp-dev libmpc3 libmpc-dev texinfo unzip && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain none
ENV PATH="/root/.cargo/bin:${PATH}"
# Not sure why/if this is needed
ENV LIBRARY_PATH=/usr/lib
# Make sure we compile to the right target
ENV OVERWRITE_TARGET_TRIPLE=m68k-elf

RUN mkdir /build
WORKDIR /build

# Install binutils
RUN curl -L https://sourceware.org/pub/binutils/releases/binutils-2.43.tar.xz | tar xJ
RUN mkdir binutils-build && cd binutils-build && \
    ../binutils-2.43/configure --prefix=/usr/local --target=m68k-elf --disable-multilib && \
    make -j $(nproc) && \
    make install && \
    cd /build && rm -rf /build/binutils-2.43 /build/binutils-build

# Install GCC
RUN git clone https://github.com/antoyo/gcc --depth=2
RUN mkdir gcc-build && cd gcc-build && \
    ../gcc/configure \
        --enable-host-shared \
        --enable-languages=jit \
        --enable-checking=release \
        --disable-bootstrap \
        --disable-multilib \
        --prefix=/usr/local \
        --with-cpu=m68000 \
        --with-arch=m68k \
	    --disable-libmudflap --disable-libgomp --disable-libssp --disable-libquadmath \
	    --disable-libquadmath-support --disable-libsanitizer --disable-libmpx --disable-libstdcxx-verbose \
	    --without-zstd --disable-threads --disable-tls --disable-cet \
        --without-headers \
        --target=m68k-elf && \
    make -j $(nproc) && \
    make -j $(nproc) all-target-libgcc && \
    make install && \
    make install-target-libgcc && \
    rm -rf /build/gcc-build /build/gcc

# Clone source repo
RUN git clone https://github.com/rust-lang/rustc_codegen_gcc.git

# Set gcc path in the rustc_codegen project
RUN echo 'gcc-path = "/usr/local/lib"' > rustc_codegen_gcc/config.toml

# Setup rustup
RUN cd rustc_codegen_gcc && rustup show

# Git config is needed for ./y.sh prepare
RUN git config --global user.email "user@example.com"
RUN git config --global user.name "User"

# Apply hacky patch
COPY 0001-codegen-add-support-for-megadrive.patch /tmp/0001-codegen-add-support-for-megadrive.patch
RUN cd rustc_codegen_gcc && patch -p1 < /tmp/0001-codegen-add-support-for-megadrive.patch && rm /tmp/0001-codegen-add-support-for-megadrive.patch

ENV CHANNEL=release
# Build project
# See https://github.com/rust-lang/rustc_codegen_gcc/blob/master/doc/tips.md#how-to-build-a-cross-compiling-libgccjit
RUN cd rustc_codegen_gcc && ./y.sh prepare --cross
ENV CG_RUSTFLAGS="-Cpanic=abort -Crelocation-model=static -Copt-level=3 -Cllvm-args=-flto"

# Build both, dev + release build
RUN cd rustc_codegen_gcc && ./y.sh build --sysroot --features compiler_builtins/no-f16-f128 --target-triple m68k-unknown-linux-gnu --target /build/rustc_codegen_gcc/target_specs/m68k-unknown-linux-gnu.json
RUN cd rustc_codegen_gcc && ./y.sh build --sysroot --features compiler_builtins/no-f16-f128 --target-triple m68k-unknown-linux-gnu --target /build/rustc_codegen_gcc/target_specs/m68k-unknown-linux-gnu.json --release

## Build "megapong" PoC (as a test whether the build succeeds.
RUN git clone https://github.com/ricky26/rust-mega-drive.git
COPY 0001-Make-project-compile-with-GCC.patch /tmp/rust-mega-drive.patch
RUN cd rust-mega-drive && patch -p1 < /tmp/rust-mega-drive.patch && rm /tmp/rust-mega-drive.patch
## Compile rust code
RUN cd rustc_codegen_gcc && ./y.sh cargo build --target /build/rustc_codegen_gcc/target_specs/m68k-unknown-linux-gnu.json --manifest-path /build/rust-mega-drive/examples/megapong/Cargo.toml --release
RUN cd rustc_codegen_gcc && ./y.sh cargo build --target /build/rustc_codegen_gcc/target_specs/m68k-unknown-linux-gnu.json --manifest-path /build/rust-mega-drive/examples/megapong/Cargo.toml
#
# Compile entrypoint + stdlib stub (should not be strictly necessary to reproduce)
RUN cd rust-mega-drive/examples/megapong && m68k-elf-gcc -fno-exceptions -mcpu=68000 -T /build/rust-mega-drive/share/ldscripts/megadrive.x entry.S hack.c /build/rust-mega-drive/target/m68k-unknown-linux-gnu/release/libmegapong.a -o out.elf -O2 -nostartfiles -nostdlib -static -nolibc -s -flto -Wl,-gc-sections -ffunction-sections -fdata-sections -ffreestanding -fno-builtin
RUN cd rust-mega-drive/examples/megapong && m68k-elf-objcopy -O binary out.elf out.md

#
# ===== Actual toolchain container (split to save some space) =====
#
FROM ubuntu:22.04 AS mega
RUN mkdir -p /build /root/.cargo

# The rustc_codegen_gcc project always wants to build some system crates, so we need
# to have some packages installed.
RUN apt-get -y update && apt-get install -y --no-install-recommends \
    python3 python3-png \
    curl ca-certificates build-essential && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain none
COPY --from=builder /usr/local /usr/local
COPY --from=builder /build/rustc_codegen_gcc /build/rustc_codegen_gcc

ENV PATH="/root/.cargo/bin:${PATH}"
# Not sure why/if this is needed
ENV LIBRARY_PATH=/usr/lib
# Make sure we compile to the right target
ENV OVERWRITE_TARGET_TRIPLE=m68k-elf
RUN cd /build/rustc_codegen_gcc && rustup show
ENV CG_RUSTFLAGS="-Cpanic=abort -Crelocation-model=static -Cllvm-args=-flto"
