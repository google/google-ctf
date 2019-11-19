FROM ubuntu:19.04

RUN apt update && apt upgrade -y

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

COPY attachments/supervisor /home/user/
COPY attachments/sandbox /home/user/
COPY flag /home/user/

RUN set -e -x; \
    chown -R root:root /home/user; \
    chmod 555 /home/user; \
    chmod 555 /home/user/supervisor; \
    chmod 555 /home/user/sandbox; \
    chmod 444 /home/user/flag

USER user
CMD cd /home/user && ./supervisor
