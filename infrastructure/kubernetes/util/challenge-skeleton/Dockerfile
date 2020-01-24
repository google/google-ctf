FROM eu.gcr.io/gctf-k8s/nsjail

RUN apt-get -y update
RUN apt-get -y upgrade

COPY files /home/user
COPY config/nsjail.cfg /nsjail.cfg

CMD /bin/sh -c "/usr/bin/setup_cgroups.sh && su user -c '/usr/bin/nsjail --config /nsjail.cfg'"
