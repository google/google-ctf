# Copyright 2022 Google LLC
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
FROM ubuntu:18.04

WORKDIR /build

# Install any needed packages specified in requirements.txt
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
      build-essential \
      git \
      bzip2 \
      bsdmainutils \
      wget && \
    apt-get clean

RUN wget -qO- https://developer.arm.com/-/media/Files/downloads/gnu-rm/7-2018q2/gcc-arm-none-eabi-7-2018-q2-update-linux.tar.bz2 | tar -xj

ENV PATH "/build/gcc-arm-none-eabi-7-2018-q2-update/bin:$PATH"

RUN mkdir -p /build/firmware/third_party
COPY third_party/ELMO/Examples/Whitepaper_examples/Bytewise_MaskedAES_C/Original/elmoasmfunctions.s /build/firmware
COPY third_party/ELMO/Examples/Whitepaper_examples/Bytewise_MaskedAES_C/Original/elmoasmfunctionsdef.h /build/firmware
COPY third_party/ELMO/Examples/Whitepaper_examples/Bytewise_MaskedAES_C/Original/vector.o /build/firmware
COPY firmware/Makefile /build/firmware/Makefile
COPY firmware/firmware.ld /build/firmware/firmware.ld
COPY firmware/main.c /build/firmware/main.c
ADD  third_party/PQClean /build/firmware/third_party/PQClean
RUN sed -i 's/exit(111);/\{endprogram(); for(;;)\{\} \}/' /build/firmware/third_party/PQClean/common/aes.c
RUN sed -i 's/exit(111);/\{endprogram(); for(;;)\{\} \}/' /build/firmware/third_party/PQClean/common/sha2.c
RUN sed -i 's/PQCLEAN_KYBER51290S_CLEAN_polyvec_basemul_acc_montgomery(\&mp, \&skpv, \&b);/starttrigger();PQCLEAN_KYBER51290S_CLEAN_polyvec_basemul_acc_montgomery(\&mp, \&skpv, \&b);endtrigger();/' /build/firmware/third_party/PQClean/crypto_kem/kyber512-90s/clean/indcpa.c

RUN make -B -C /build/firmware
RUN cd /build && tar cfvz firmware.tgz firmware/

CMD sleep 1
