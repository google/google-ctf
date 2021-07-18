# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Sajjad "JJ" Arshad (sajjadium)

FROM ubuntu:20.04

RUN /usr/sbin/useradd --no-create-home -u 1000 user

RUN set -e -x; \
        apt update -y; \
        apt upgrade -y; \
	apt install -y software-properties-common; \
	apt install -y openjdk-11-jdk; \
	apt install -y unzip wget socat; \
	apt install -y cpu-checker qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst virt-manager;

RUN set -e -x; \
	wget https://dl.google.com/android/repository/commandlinetools-linux-6514223_latest.zip -O commandlinetools.zip; \
	mkdir -p /opt/android/sdk/cmdline-tools; \
	unzip commandlinetools.zip; \
	mv tools /opt/android/sdk/cmdline-tools/latest; \
	rm commandlinetools.zip;

ENV PATH "/opt/android/sdk/cmdline-tools/latest/bin:${PATH}"
ENV ANDROID_SDK_ROOT "/opt/android/sdk"

RUN set -e -x; \
	yes | sdkmanager --install \
		"cmdline-tools;latest" \
		"platform-tools" \
		"build-tools;30.0.0" \
		"platforms;android-30" \
		"system-images;android-30;google_apis;x86_64" \
		"emulator";

RUN sdkmanager --update;

ENV PATH "/opt/android/sdk/emulator:${PATH}"
ENV PATH "/opt/android/sdk/platform-tools:${PATH}"
ENV PATH "/opt/android/sdk/build-tools/30.0.0:${PATH}"

COPY flag server.py app.apk /challenge/
RUN chmod 755 /challenge/server.py
RUN chmod 644 /challenge/app.apk /challenge/flag

RUN mkdir /home/user/
RUN chmod 755 /home/user/

CMD chmod 0777 /dev/kvm && \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"/challenge/server.py"
