FROM ubuntu:18.04
LABEL maintainer="David Wearing <wearing@google.com>"
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y qemu qemu-user-static
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user
COPY bof /home/user/
COPY console /home/user/
COPY flag0 /home/user/
COPY flag1 /home/user/
RUN set -e -x ;\
     chown -R root:root /home/user; \
     chmod 0755 /home/user; \
     chmod 0755 /home/user/bof; \
     chmod 0755 /home/user/console; \
     chmod 0755 /home/user/flag0; \
     chmod 0755 /home/user/flag1;
USER user
CMD cd /home/user && ./console

