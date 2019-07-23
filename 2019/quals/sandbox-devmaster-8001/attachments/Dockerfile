# If you wish, you can use this Dockerfile to run the DevMaster 8000 locally.
# It approximates the environment in which the DevMaster 8000 is run in the cloud.

FROM ubuntu:16.04
RUN set -e -x; \
        apt-get -y update; \
        apt-get -y upgrade; \
	apt-get install -y software-properties-common; \
	add-apt-repository -y ppa:ubuntu-toolchain-r/test; \
	apt-get -y update; \
	apt-get -y upgrade libstdc++6; \
	apt-get install -y python2.7; \
	apt-get install -y g++
RUN set -e -x; \
  groupadd -g 1338 sandbox-runner-0; \
	useradd -g 1338 -u 1338 -r -s /bin/false sandbox-runner-0; \
  groupadd -g 1339 sandbox-runner-1; \
	useradd -g 1339 -u 1339 -r -s /bin/false sandbox-runner-1; \
  groupadd -g 1340 sandbox-runner-2; \
	useradd -g 1340 -u 1340 -r -s /bin/false sandbox-runner-2; \
  groupadd -g 1341 sandbox-runner-3; \
	useradd -g 1341 -u 1341 -r -s /bin/false sandbox-runner-3; \
  groupadd -g 1342 sandbox-runner-4; \
	useradd -g 1342 -u 1342 -r -s /bin/false sandbox-runner-4; \
  groupadd -g 1343 sandbox-runner-5; \
	useradd -g 1343 -u 1343 -r -s /bin/false sandbox-runner-5; \
  groupadd -g 1344 sandbox-runner-6; \
	useradd -g 1344 -u 1344 -r -s /bin/false sandbox-runner-6; \
  groupadd -g 1345 sandbox-runner-7; \
	useradd -g 1345 -u 1345 -r -s /bin/false sandbox-runner-7; \
  groupadd -g 1346 admin; \
	useradd -g 1346 -u 1346 -r -s /bin/false admin;

COPY built_bins/* /home/user/
RUN  echo "On the server, this would be the real flag" > /home/user/flag
COPY src/admin.cc /home/user/admin.cc
COPY src/third_party/picosha2.h /home/user/picosha2.h
COPY target_loop.sh /home/user/target_loop.sh
COPY challenge.sh /home/user/challenge.sh

RUN set -e -x; \
        mkdir /home/user/builds

RUN set -e -x; \
	chown -R 0:0 /home/user; \
	chmod -R 554 /home/user/*; \
	find /home/user/ -type d -exec chmod 775 {} +; \
	chown admin:admin /home/user/flag; \
	chmod 440 /home/user/flag; \
	chown admin:admin /home/user/admin; \
	chown 0:0 /home/user/drop_privs; \
	chmod 6744 /home/user/drop_privs;

USER root
CMD cd /home/user && ./challenge.sh

