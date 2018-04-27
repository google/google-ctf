FROM ubuntu:17.04
RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	make \
	gcc \
	tar

RUN set -e -x ;\
  groupadd -g 1337 jail1 ;\
  useradd -g 1337 -u 1337 -m jail1

RUN mkdir /home/jail1/build

COPY challenge/jail.tar /home/jail1/build
RUN tar -C /home/jail1/build -xf /home/jail1/build/jail.tar
RUN cat /home/jail1/build/init.c
RUN make -C /home/jail1/build all
RUN cp /home/jail1/build/jail /home/jail1/jail
RUN cp /home/jail1/build/init /home/jail1/init
RUN rm -rf /home/jail1/build

COPY challenge/flag.txt /home/jail1

RUN set -e -x ;\
	chown -R jail1:jail1 /home/jail1 ;\
	chmod -R 755 /home/jail1
