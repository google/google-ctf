FROM ubuntu:xenial

RUN apt-get update


# Use UTF-8
RUN apt-get install -y locales
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN apt-get install -y socat

# For debugging
RUN apt-get install -y vim-common
RUN apt-get install -y less
RUN apt-get install -y gdb-multiarch
RUN apt-get install -y git
RUN apt-get install -y sudo

RUN git clone https://github.com/pwndbg/pwndbg.git
RUN cd pwndbg && bash setup.sh

RUN git clone https://github.com/Gallopsled/pwntools.git
RUN cd pwntools && pip install -Ue .

RUN apt-get install -y tmux


RUN mkdir                /challenge
WORKDIR                  /challenge
COPY qemu-arm            /challenge/
COPY superman            /challenge/
COPY close               /challenge/
COPY hello_world.payload /challenge/

# ENTRYPOINT socat TCP-LISTEN:1337,fork,reuseaddr,bind=0.0.0.0 EXEC:"./qemu-arm ./superman"

