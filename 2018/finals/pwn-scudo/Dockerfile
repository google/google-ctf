FROM ubuntu:18.04
RUN set -e -x; \
        apt-get -y update; \
        apt-get -y upgrade
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user
COPY attachments/scudo /home/user/scudo
COPY challenge/flag /home/user/flag
RUN set -e -x ;\
        chmod 0555 /home/user/scudo; \
        chmod 0444 /home/user/flag
USER user
CMD cd /home/user && ./scudo
