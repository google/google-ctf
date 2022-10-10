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

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
      python3 \
      python3-pip \
      bsdmainutils && \
    python3 -m pip install pycrypto numpy scipy && \
    apt-get clean

# Key is the first 16 bytes in data.txt
COPY flag /build/flag
RUN cat /build/flag | sed 's/^CTF{\(.*\)}$/\1/' | tr -d '\n' | hexdump -ve '1/1 "%.2x\n"' > /build/data.txt

# ELMO executable and runtime dependencies.
COPY elmo.tgz /build/
RUN cd /build && tar xfvz elmo.tgz --strip=1 ELMO/elmo ELMO/coeffs.txt

# Target firmware binary.
COPY firmware.tgz /build/
RUN cd /build && tar xfvz firmware.tgz --strip=1 firmware/firmware.bin

# Produce power traces.
RUN cd /build && ./elmo firmware.bin -Ntrace 50

# Collect plaintext (randdata), ciphertext (printdata) and traces.
COPY traces/collect.py /build/collect.py
RUN cd /build && \
    python3 collect.py \
            --plaintext output/randdata.txt \
            --ciphertext output/printdata.txt \
            --tracedir output/traces/trace%05d.trc \
            --ntraces 50 \
            traces_raw.json.gz

COPY traces/downsample.py /build/downsample.py
RUN cd /build && \
    python3 downsample.py \
            --input traces_raw.json.gz \
            --factor 5 \
            traces.json.gz

CMD sleep 1
