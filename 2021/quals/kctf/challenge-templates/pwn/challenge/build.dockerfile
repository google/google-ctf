FROM ubuntu:20.04 as build

RUN apt-get update && apt-get install -yq --no-install-recommends build-essential

RUN mkdir /build
COPY chal.c /build/
RUN make -C /build chal

CMD sleep 1
