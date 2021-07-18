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

FROM ubuntu:20.04 as build

RUN set -e -x; \
        apt update -y; \
        apt upgrade -y; \
	apt install -y software-properties-common; \
	apt install -y openjdk-11-jdk; \
	apt install -y unzip wget less;

RUN set -e -x; \
	wget https://dl.google.com/android/repository/commandlinetools-linux-6514223_latest.zip -O commandlinetools.zip; \
	mkdir -p /opt/android/sdk/cmdline-tools; \
	unzip commandlinetools.zip; \
	mv tools /opt/android/sdk/cmdline-tools/latest; \
	rm commandlinetools.zip;

RUN set -e -x; \
	wget https://services.gradle.org/distributions/gradle-7.1.1-bin.zip; \
	mkdir -p /opt/gradle; \
	unzip gradle-7.1.1-bin.zip -d /opt/gradle; \
	rm gradle-7.1.1-bin.zip;

ENV PATH "/opt/android/sdk/cmdline-tools/latest/bin:${PATH}"
ENV PATH "/opt/gradle/gradle-7.1.1/bin:${PATH}"
ENV ANDROID_SDK_ROOT "/opt/android/sdk"

RUN set -e -x; \
	yes | sdkmanager --install \
		"cmdline-tools;latest" \
		"build-tools;30.0.0"

RUN sdkmanager --update;

ENV PATH "/opt/android/sdk/build-tools/30.0.0:${PATH}"

RUN mkdir /build
COPY src /build
RUN cd /build && gradle wrapper build

CMD sleep 1

