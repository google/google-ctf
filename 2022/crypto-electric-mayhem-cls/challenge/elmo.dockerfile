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

ADD third_party/ELMO /build/ELMO
# RUN sed -i 's/DBUG        0/DBUG 1/' /build/ELMO/elmodefines.h
RUN sed -i 's/#define FIXEDVSRANDOM$/#undef FIXEDVSRANDOM/' /build/ELMO/elmodefines.h
RUN sed -i 's/DATAFILEPATH "Examples\/randdata100000.txt"/DATAFILEPATH "data.txt"/' /build/ELMO/elmodefines.h
RUN sed -i 's/srand((unsigned) time(&timet));/srand(1234);/' /build/ELMO/elmo.c
RUN make -B -C /build/ELMO clean elmo
RUN cd /build && tar cfvz elmo.tgz ELMO/elmo* ELMO/coeffs* ELMO/Makefile ELMO/include/*.h

CMD sleep 1
