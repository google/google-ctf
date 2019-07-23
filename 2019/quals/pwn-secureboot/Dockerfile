FROM ubuntu:18.04
RUN set -e -x ;\
	groupadd -g 1337 sb; \
	useradd -g 1337 -u 1337 -m sb
COPY OVMF.fd run.py /home/sb/
COPY contents/ /home/sb/contents/
RUN set -e -x ;\
	chown -R root:root /home/sb; \
	chmod 0755 /home/sb; \
	chmod 0755 /home/sb/run.py; \
	chmod 0444 /home/sb/OVMF.fd; \
	chmod 0444 /home/sb/contents/*; \
  apt-get update; \
  apt-get install -y python3 qemu-system-x86
USER sb
CMD cd /home/sb && ./run.py

