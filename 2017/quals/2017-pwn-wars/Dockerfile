FROM ubuntu:14.04

RUN set -e -x ;\
        groupadd -g 1337 pwnwars ;\
        useradd -g 1337 -u 1337 -m pwnwars

COPY attachments/pwnwars /home/pwnwars
COPY flag.txt /home/pwnwars

RUN set -e -x ;\
        chown -R pwnwars:pwnwars /home/pwnwars ;\
        chmod -R 755 /home/pwnwars

