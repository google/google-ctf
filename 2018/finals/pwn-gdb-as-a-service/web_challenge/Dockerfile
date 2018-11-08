FROM ubuntu:18.04

RUN apt-get update
RUN apt-get upgrade -y
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

RUN apt-get install -y python3 python3-pip
RUN pip3 install virtualenv
RUN apt-get install -y gdbserver

RUN virtualenv /env -p python3

ENV VIRTUAL_ENV /env
ENV PATH /env/bin:$PATH
ENV PREMIUM=1
ENV PREMIUM_KEY=pee6ecei5ef8ahZu2xiF

ADD challenge/requirements.txt /home/user/
ADD challenge/gunicorn.conf.py /home/user/
ADD challenge/gaas.py /home/user/
ADD challenge/gdbproc.py /home/user/
ADD challenge/index.html /home/user/
ADD challenge/printwebflag /home/user/

RUN set -e -x; \
        chown -R root:root /home/user; \
        chmod 0555 /home/user/gunicorn.conf.py; \
        chmod 0555 /home/user/gaas.py; \
        chmod 0555 /home/user/gdbproc.py; \
        chmod 0555 /home/user/printwebflag; \
        chmod 0444 /home/user/index.html

RUN pip install -r /home/user/requirements.txt

USER user
CMD cd /home/user && gunicorn -c gunicorn.conf.py -b :$PORT gaas:app
