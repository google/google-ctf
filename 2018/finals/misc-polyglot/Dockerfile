from base/archlinux

RUN pacman -Syy
RUN pacman -Sy --noconfirm docker python2
RUN pacman -Sy --noconfirm python2-docker
RUN pacman -Sy --noconfirm socat
copy general.image /
add polyglot.py /

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

RUN set -e -x ;\
        chmod 0555 /polyglot.py;
RUN set -e -x ;\
        chmod 0555 /general.image;

EXPOSE 1337
CMD socat tcp-l:1337,fork exec:'python2 -u /polyglot.py'
