FROM ubuntu:17.04
RUN set -e -x ;\
        groupadd -g 1337 trash ;\
        useradd -g 1337 -u 1337 -m trash
COPY challenge/trash /home/trash
COPY challenge/flag.txt /home/trash
RUN set -e -x ;\
        chown -R trash:trash /home/trash ;\
        chmod -R 755 /home/trash
