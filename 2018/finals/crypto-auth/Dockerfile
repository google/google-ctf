FROM base/archlinux
RUN pacman -Syy
RUN pacman -S --noconfirm openssl socat shadow
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user
ADD auth /
ADD flag.txt /
RUN set -e -x ;\
        chmod 0555 /auth;
EXPOSE 1337
CMD socat tcp-l:1337,fork exec:'/auth'

