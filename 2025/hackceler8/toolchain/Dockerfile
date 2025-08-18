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
RUN git clone --no-checkout https://github.com/antoyo/gcc --depth=2
RUN cd gcc && git checkout 4e995bd73c4490edfe5080ec6014d63aa9abed5f
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
RUN git clone --no-checkout https://github.com/rust-lang/rustc_codegen_gcc.git
RUN cd rustc_codegen_gcc && git checkout 962a08ff4a3ea6f9b616bc821e8eaeb3d27a57a4

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
