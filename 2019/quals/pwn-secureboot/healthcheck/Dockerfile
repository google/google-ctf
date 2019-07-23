FROM ubuntu:18.04
RUN apt-get update && apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential python3-pip -y
RUN pip3 install nameko
RUN pip install git+https://github.com/Gallopsled/pwntools.git@dev
RUN set -e -x ;\
    groupadd -g 1337 app; \
    useradd -g 1337 -u 1337 -m app; \
    mkdir /app

ADD solve.py /app/
ADD config.yaml /app/
ADD healthcheck.py /app/
RUN set -e -x ;\
        chown -R app /app
USER app
WORKDIR /app
EXPOSE 5000
CMD nameko run --config config.yaml healthcheck
