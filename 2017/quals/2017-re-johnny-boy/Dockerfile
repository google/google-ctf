FROM ubuntu:16.10
RUN apt-get update && apt-get install -y wget xz-utils openjdk-8-jre xvfb python python-pil

ENV ARDUINO_IDE_VERSION 1.8.1
RUN wget -q -O /opt/arduino.tar.xz https://downloads.arduino.cc/arduino-${ARDUINO_IDE_VERSION}-linux64.tar.xz && tar xvf /opt/arduino.tar.xz -C /opt/
ENV DISPLAY :0
ENV ARDUINO_PATH /opt/arduino-${ARDUINO_IDE_VERSION}
RUN xvfb-run -a ${ARDUINO_PATH}/arduino --install-library Arduboy
RUN xvfb-run -a ${ARDUINO_PATH}/arduino --install-library Arduboy2
RUN xvfb-run -a ${ARDUINO_PATH}/arduino --install-library ArduboyTones
RUN xvfb-run -a ${ARDUINO_PATH}/arduino --install-library ArduboyPlaytune

COPY chall /tmp/chall
ARG flag
RUN cd /tmp/chall/ && python generate_image.py ${flag}
ENV PATH ${PATH}:${ARDUINO_PATH}/hardware/tools/avr/bin/
RUN mkdir /tmp/build && xvfb-run -a ${ARDUINO_PATH}/arduino-builder -compile \
    -hardware ${ARDUINO_PATH}/hardware \
    -tools ${ARDUINO_PATH}/hardware/tools/ \
    -tools ${ARDUINO_PATH}/tools-builder \
    -libraries /root/Arduino/libraries \
    -fqbn arduino:avr:leonardo \
    -build-path /tmp/build \
    /tmp/chall/chall.ino
