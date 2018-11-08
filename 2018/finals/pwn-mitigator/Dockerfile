FROM ubuntu:18.04
RUN set -e -x; \
        apt-get -y update; \
        apt-get -y upgrade; \
	apt-get -y install socat strace; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user
COPY challenge/http /home/user/http
COPY challenge/run.sh /home/user/run.sh
COPY challenge/flag /home/user/flag
COPY challenge/www /home/user/www
COPY challenge/apparmor/jail.apparmor /etc/apparmor.d/jail
RUN set -e -x ;\
        chown -R root:root /home/user; \
	chmod 0555 /home/user; \
        chmod 0555 /home/user/http; \
        chmod 0555 /home/user/run.sh; \
        chmod 0444 /home/user/flag; \
	chmod -R 0444 /home/user/www; \
	chmod 0555 /home/user/www; \
	chmod 0555 /home/user/www/cgi-bin; \
	chmod 0555 /home/user/www/cgi-bin/login-to-sem.sh; \
	chmod 0555 /home/user/www/css; \
	chmod 0555 /home/user/www/images; \
	chmod 0555 /home/user/www/.well-known
USER user
CMD cd /home/user && ./run.sh
