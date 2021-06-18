FROM alpine:3
WORKDIR /usr/challenge
COPY ./modded.py .
RUN chmod a+rx ./modded.py
RUN apk add socat
RUN apk add python3
RUN apk add python3-dev
RUN apk add gcc
RUN apk add py3-pip
RUN apk add musl-dev
RUN apk add linux-headers
RUN apk add gmp-dev
RUN apk add mpfr-dev
RUN apk add mpc1-dev
RUN python3 -m pip install gmpy2
EXPOSE 1
CMD while true; do socat tcp-l:1,reuseaddr,fork 'exec:/usr/challenge/modded.py'; done
