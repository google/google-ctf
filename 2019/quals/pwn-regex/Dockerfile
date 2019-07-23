FROM ubuntu:18.04
RUN set -e -x; \
      apt-get -y update; \
      apt-get -y upgrade
RUN set -e -x; \
      groupadd -g 1337 user; \
      useradd -g 1337 -u 1337 -m user
COPY attachments/regex /home/user/
COPY src/flag /home/user/
RUN set -e -x ;\
      chown -R root:root /home/user; \
      chmod 0755 /home/user; \
      chmod 0755 /home/user/regex; \
      chmod 0744 /home/user/flag
USER user
CMD cd /home/user && ./regex

