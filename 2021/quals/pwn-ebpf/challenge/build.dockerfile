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
FROM ubuntu:20.04 as build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -yq --no-install-recommends \
	build-essential \
	flex \
	bison \
	wget \
	bc \
	ca-certificates \
	libelf-dev \
	libssl-dev \
        python3 \
        cpio

RUN mkdir -p /build

WORKDIR /build

COPY kernel.config /build/
COPY bpf_verifier.h.patch /build/
COPY verifier.c.patch /build/

RUN wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.12.2.tar.xz && \
	tar -xf linux-5.12.2.tar.xz && \
	mv linux-5.12.2 linux && \
        patch linux/kernel/bpf/verifier.c verifier.c.patch && \
        patch linux/include/linux/bpf_verifier.h bpf_verifier.h.patch && \
	cd linux && \
	cp ../kernel.config .config && \
	make -j`nproc` && \
        nm vmlinux > ../symbols.txt

RUN mkdir /build/initramfs
COPY initramfs/ /build/initramfs
COPY flag /build/
COPY gen_cpio.sh /build/

# Generate the attachments initramfs which doesn't have the flag and the real one which does
RUN echo 'ctf{fake flag}' > initramfs/flag && ./gen_cpio.sh && mv root.cpio.gz attachments-root.cpio.gz
RUN cp flag initramfs/flag && ./gen_cpio.sh
