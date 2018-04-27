FROM ubuntu:16.04

COPY corewars /corewars
RUN mkdir /warrior
COPY warrior/challenge.red /warrior
RUN set -e -x ;\
    groupadd -g 1337 user ;\
    useradd -g 1337 -u 1337 -m user
RUN set -e -x ;\
    chown -R user:user /corewars ;\
    chmod -R 755 /corewars
RUN set -e -x ;\
    chown -R user:user /warrior ;\
    chmod -R 755 /warrior
