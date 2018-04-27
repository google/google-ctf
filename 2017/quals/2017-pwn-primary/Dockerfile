# Can be others, we believe.
FROM ubuntu:14.04

RUN set -e -x ;\
        apt-get update ;\
        apt-get -y upgrade ;\
        apt-get install -y libgoogle-perftools-dev clang-3.8 ;\
        rm -rf /var/lib/apt/lists/*

RUN set -e -x ;\
        groupadd -g 1337 user ;\
        useradd -g 1337 -u 1337 -m user

COPY attachments/primary /home/user/
COPY flag.txt.doc.exe /home/user/
COPY help.txt /home/user/

RUN set -e -x ;\
        chown -R user:user /home/user ;\
        chmod -R 744 /home/user

USER user
