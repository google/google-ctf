FROM ubuntu:14.04

RUN set -e -x ;\
        groupadd -g 1337 user ;\
        useradd -g 1337 -u 1337 -m user

COPY attachments/assignment /home/user
COPY flag.txt /home/user

RUN set -e -x ;\
        chown -R user:user /home/user ;\
        chmod -R 755 /home/user

