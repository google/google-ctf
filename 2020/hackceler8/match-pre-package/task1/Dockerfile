FROM alpine:3
WORKDIR /usr/challenge
COPY ./task1.py .
RUN chmod a+rx ./task1.py
RUN apk add socat
RUN apk add python3
EXPOSE 7000
ENV TASK1_FLAG HCL8{AnotherTestFlag}
CMD while true; do socat tcp-l:7000,reuseaddr,fork 'exec:/usr/challenge/task1.py'; done
