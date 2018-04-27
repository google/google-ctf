FROM debian

RUN set -e -x ;\
        groupadd -g 1337 user ;\
        useradd -g 1337 -u 1337 -m user

ADD challenge/challenge challenge

RUN set -e -x ;\
        chown user:user /challenge ;\
        chmod 500 /challenge

USER user
CMD /challenge
