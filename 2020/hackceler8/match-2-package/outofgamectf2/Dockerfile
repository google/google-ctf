FROM alpine:3
WORKDIR /usr/challenge
COPY ./runner .
COPY ./controller.py .
COPY ./challenges/tree.py ./challenges/
RUN chmod a+rx ./runner ./controller.py
RUN chmod a+r ./challenges/tree.py
RUN apk add nasm
RUN apk add socat
RUN apk add python3
EXPOSE 4568
CMD while true; do socat tcp-l:4568,reuseaddr,fork 'exec:/usr/challenge/controller.py tree'; done
