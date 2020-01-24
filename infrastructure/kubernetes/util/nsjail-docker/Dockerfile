FROM ubuntu:19.10

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y uidmap
RUN apt-get install -y build-essential git protobuf-compiler libprotobuf-dev bison flex pkg-config libnl-route-3-dev
RUN git clone https://github.com/google/nsjail.git
RUN cd /nsjail && make && cp nsjail /usr/bin/
RUN rm -R /nsjail

RUN useradd --no-create-home -u 1000 user

RUN apt-get install -y libprotobuf17
RUN apt-get install -y python3
RUN apt-get install -y libnl-route-3-200

COPY setup_cgroups.sh /usr/bin/
COPY proof_of_work/pow.py /usr/bin/
COPY proof_of_work/maybe_pow.sh /usr/bin/
