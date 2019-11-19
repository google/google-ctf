FROM python:3-slim-stretch
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user
RUN pip3 install cryptography
COPY challenge.py vmac64.py /home/user/
COPY data/ /home/user/data
RUN set -e -x ;\
        chmod 0444 /home/user/challenge.py /home/user/vmac64.py; \
        chmod 0555 /home/user/data; \
        chmod 0444 /home/user/data/*
