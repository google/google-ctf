FROM ubuntu:17.04

RUN apt-get update
RUN apt-get install -y python

RUN set -e -x ;\
        groupadd -g 1337 user ;\
        useradd -g 1337 -u 1337 -m user
COPY checker/hasher.py /home/user
COPY checker/checker.py /home/user
COPY checker/farnsworth_fry_will /home/user
COPY metadata.json /home/user
RUN set -e -x ;\
        chown -R user:user /home/user ;\
        chmod -R 755 /home/user
