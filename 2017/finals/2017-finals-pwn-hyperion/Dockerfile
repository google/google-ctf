FROM ubuntu:17.04

RUN set -e -x ;\
    groupadd -g 1337 hyperion ;\
    useradd -g 1337 -u 1337 hyperion

ADD hyperion_server /hyperion_server
ADD flag /flag

RUN set -e -x ;\
    chown hyperion:hyperion /hyperion_server ;\
    chmod a+r /flag ;\
    chmod a+rx /hyperion_server

USER hyperion 

# TEST ONLY

# This env variable needs only to be set if the challenge is supposed to run as
# a full TCP server. I.e. in the competition environment it MUST NOT be set.
ENV HYPERION_FORK_SERVER 1
CMD /hyperion_server
EXPOSE 1337

# --- TEST ONLY



