FROM ubuntu:16.04

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

ADD bin/service /service
RUN set -e -x ;\
        chown user /service ;\
        chmod 555 /service

CMD service --local
