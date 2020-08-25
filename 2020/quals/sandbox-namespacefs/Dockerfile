FROM ubuntu:20.04

RUN apt-get update && apt-get upgrade -y

RUN apt-get -y install libprotobuf17 libcap2

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

COPY src/nsfs /home/user/
COPY src/init /home/user/
COPY flag /home/user/

RUN set -e -x; \
    chown -R root:root /home/user; \
    chmod 555 /home/user; \
    chmod 555 /home/user/nsfs; \
    chmod 555 /home/user/init

RUN set -e -x; \
    chown 1337:1337 /home/user/flag; \
    chmod 400 /home/user/flag

USER user
CMD cd /home/user && ./nsfs
