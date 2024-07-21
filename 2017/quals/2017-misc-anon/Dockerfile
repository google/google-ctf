FROM debian
LABEL maintainer "rjamet@"

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

RUN apt-get update
RUN apt-get --no-install-recommends install -y apt-utils ca-certificates apt-transport-https perl
RUN apt-get --no-install-recommends install -y apt-utils ca-certificates apt-transport-https netcat
RUN apt-get --no-install-recommends install -y apt-utils ca-certificates apt-transport-https libjson-perl libdigest-hmac-perl

ADD ./misc_rjamet.pl /chall/
ADD ./flag.txt /chall/

WORKDIR /chall/

RUN chmod +x ./misc_rjamet.pl

EXPOSE 1337
CMD nc.traditional -l -p 1337 -e ./misc_rjamet.pl
