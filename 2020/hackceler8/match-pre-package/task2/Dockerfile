FROM alpine:3
WORKDIR /usr/challenge
COPY ./task2.py .
RUN chmod a+rx ./task2.py
RUN apk add socat
RUN apk add python3
EXPOSE 7001
ENV TASK2_FLAG HCL8{IAmFlag}
CMD while true; do socat tcp-l:7001,reuseaddr,fork 'exec:/usr/challenge/task2.py'; done
