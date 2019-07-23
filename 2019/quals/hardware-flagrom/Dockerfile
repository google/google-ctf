FROM ubuntu:19.04
RUN set -e -x; \
    apt-get -y update; \
    apt-get -y upgrade; \
    apt-get -y install openssl
RUN set -e -x; \
    groupadd -g 1337 user; \
    useradd -g 1337 -u 1337 -m user
COPY serverside/* /home/user/
RUN set -e -x; \
    chmod 0555 /home/user/flagrom; \
    chmod 0444 /home/user/firmware.8051; \
    chmod 0444 /home/user/flag.txt
USER user
CMD cd /home/user && ./flagrom

