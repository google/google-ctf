FROM ubuntu:16.04
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user
COPY comms_sat /home/user
RUN set -e -x; \
    chown -R user:user /home/user; \
    chmod 700 /home/user; \
    chmod 700 /home/user/comms_sat; \
