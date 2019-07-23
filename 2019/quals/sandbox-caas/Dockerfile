FROM ubuntu:16.04

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

COPY attachments/challenge /home/user/
COPY flag /home/user/flag

RUN set -e -x; \
    chown -R user:user /home/user; \
    chmod 700 /home/user; \
    chmod 700 /home/user/challenge; \
    chmod 400 /home/user/flag;

USER user
CMD cd /home/user && ./challenge

