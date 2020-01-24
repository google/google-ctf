FROM eu.gcr.io/gctf-k8s/nsjail

RUN apt-get -y update
RUN apt-get -y upgrade

COPY files /home/user
COPY config/nsjail.cfg /nsjail.cfg

CMD /usr/bin/setup_cgroups.sh && exec setpriv --init-groups --reset-env --reuid user --regid user --inh-caps=-all -- /usr/bin/nsjail --config /nsjail.cfg
