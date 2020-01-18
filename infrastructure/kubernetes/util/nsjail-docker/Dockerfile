FROM ubuntu

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y uidmap
RUN useradd --no-create-home -u 1000 user

RUN apt-get install -y libprotobuf10
RUN apt-get install -y python2.7

COPY nsjail/nsjail /usr/bin/
COPY setup_cgroups.sh /usr/bin/
COPY proof_of_work/pow.py /usr/bin/
COPY proof_of_work/maybe_pow.sh /usr/bin/
