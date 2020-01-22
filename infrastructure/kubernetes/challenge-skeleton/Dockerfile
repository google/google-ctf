FROM tsuro/nsjail
COPY files /home/user
COPY nsjail.cfg /nsjail.cfg
CMD /bin/sh -c "/usr/bin/setup_cgroups.sh && su user -c '/usr/bin/nsjail --config /nsjail.cfg'"
