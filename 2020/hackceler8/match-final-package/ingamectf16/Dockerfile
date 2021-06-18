FROM alpine:3
WORKDIR /usr/challenge
COPY ./main.py .
COPY ./flag .
RUN chmod a+rx ./main.py
RUN chmod a+r ./flag
RUN apk add socat
RUN apk add python3
EXPOSE 1
CMD while true; do socat tcp-l:1,reuseaddr,fork 'exec:/usr/challenge/main.py'; done
