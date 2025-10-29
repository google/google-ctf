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

FROM openjdk:8-jdk-slim
WORKDIR /home

# 1. Create a non-root user and install all dependencies
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ant wget unzip patch && \
    useradd -m -s /bin/bash user && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. Copy challenge files into the container.
COPY flag /home/flag
COPY chal.patch /home/chal.patch
COPY start.sh /home/

# 3. Download, patch, and build CoreNLP
RUN wget https://github.com/stanfordnlp/CoreNLP/archive/refs/tags/v4.5.8.zip && \
    unzip v4.5.8.zip && \
    cd CoreNLP-4.5.8 && \
    patch -p1 < ../chal.patch && \
    ant && \
    cd classes && jar -cf ../stanford-corenlp.jar edu && cd .. && \
    cd .. && rm v4.5.8.zip && rm -f chal.patch

# 4. Set final ownership and permissions.
RUN chown -R user:user /home

# EXPERIMENTAL -- create binary that reads file, set permissions such that only binary can access file
# RUN apt-get install -y --no-install-recommends gcc && \
#   echo '#include <stdio.h>\nint main() { FILE *f = fopen("/home/flag", "r"); if (f == NULL) return 1; char c; while ((c = fgetc(f)) != EOF) putchar(c); fclose(f); return 0; }' > read_flag.c && \
#   gcc read_flag.c -o read_flag && \
#   rm read_flag.c \
#   chown root:root /home/flag && \
#   chmod 400 /home/flag && \
#   chown root:user /home/read_flag && \
#   chmod 4750 /home/read_flag



# 6. Switch from the root user to the new non-root user
USER user

VOLUME /tmp

# 7. Command to run the Stanford CoreNLP server on the correct port as 'user'
CMD /home/start.sh

# Suggested run with --network="host"
