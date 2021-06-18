FROM i386/alpine:3
WORKDIR /usr/challenge
COPY ./bin_to_run .
RUN chmod a+rx ./bin_to_run
RUN apk add socat
EXPOSE 1
CMD while true; do socat tcp-l:1,reuseaddr,fork exec:/usr/challenge/bin_to_run; done
