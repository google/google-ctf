FROM ubuntu:20.04

RUN apt-get update && \
    apt-get -y install libelf1 && \
    rm -rf /var/lib/apt/lists/*

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

COPY bin/libsimavr.so.1 /home/user/
COPY bin/simduino.elf /home/user/
COPY bin/code_server.hex /home/user/
COPY bin/ATmegaBOOT_168_atmega328.ihex /home/user/

RUN set -e -x; \
    chown -R root:root /home/user; \
    chmod 555 /home/user /home/user/simduino.elf /home/user/libsimavr.so.1; \
    chmod 444 /home/user/code_server.hex /home/user/ATmegaBOOT_168_atmega328.ihex;

USER user
ENV LD_LIBRARY_PATH /home/user/
CMD cd /home/user && ./simduino.elf ./code_server.hex
