FROM debian:stable

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install python chromium strace gdb nano libatk-bridge2.0-0 libgtk-3-0

RUN set -e -x; \
    groupadd -g 1337 user; \
    useradd -g 1337 -u 1337 -m user

COPY chrome /home/user/chrome
COPY flag /home/user/flag
COPY service.py /home/user

RUN set -e -x;\
    chmod -R 0555 /home/user/chrome/; \
    chmod 0555 /home/user/service.py; \
    chmod 0444 /home/user/flag

USER user
CMD cd /home/user && python ./service.py
