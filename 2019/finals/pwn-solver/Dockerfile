FROM debian:stretch

RUN set -e -x; \
        apt-get -y update; \
        apt-get -y upgrade

RUN set -e -x ;\
	groupadd -g 1337 sandbox; \
	useradd -g 1337 -u 1337 -m user


COPY attachments/solver flag /home/user/

RUN set -e -x ;\
	chmod 0755 /home/user/solver; \
	chmod 0644 /home/user/flag
USER user
CMD cd /home/user && ./solver
