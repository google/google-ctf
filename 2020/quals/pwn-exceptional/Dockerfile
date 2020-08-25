FROM ubuntu:20.04


RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

COPY attachments/exceptional /home/user/
COPY flag.txt /home/user

RUN set -e -x; \
    chown -R root:root /home/user; \
    chmod 555 /home/user /home/user/exceptional; \
	chmod 444 /home/user/flag.txt;

USER user
#ENV LD_LIBRARY_PATH /home/user/
CMD cd /home/user && ./exceptional
