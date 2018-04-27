FROM debian
RUN set -e -x ;\
        apt-get -y update; \
        apt-get -y install python2.7
COPY attachments/cfi /cfi
COPY challenge/pow.py /pow.py
COPY challenge/hashcash.py /hashcash.py
ADD attachments/toolchain.tar.gz /
RUN set -e -x ;\
        groupadd -g 1337 user ;\
        useradd -g 1337 -u 1337 -m user
COPY challenge/flag.txt /flag.txt
ENV MCFI_SDK /toolchain
RUN set -e -x ;\
        chmod 755 /cfi; \
        chmod 755 /pow.py; \
        chmod 755 /hashcash.py; \
        chmod 444 /flag.txt
USER user
CMD MCFI_SDK=/toolchain /pow.py /cfi
