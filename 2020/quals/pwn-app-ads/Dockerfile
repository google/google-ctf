# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:20.04
RUN set -e -x; \
        apt-get update -y; \
        apt-get upgrade -y; \
	apt-get install -y software-properties-common; \
	apt-get install -y default-jdk; \
	apt-get install -y unzip wget less;

RUN set -e -x; \
        groupadd -g 1337 user; \
	useradd -g 1337 -u 1337 -m user

ENV GRADLE_VERSION "6.5"

RUN set -e -x; \
	wget https://downloads.gradle-dn.com/distributions/gradle-${GRADLE_VERSION}-bin.zip; \
	unzip -d /opt gradle-${GRADLE_VERSION}-bin.zip; \
	mv /opt/gradle-${GRADLE_VERSION} /opt/gradle; \
	rm gradle-${GRADLE_VERSION}-bin.zip;

ENV PATH "/opt/gradle/bin:${PATH}"

RUN set -e -x; \
	mkdir /opt/gradlew; \
	cd /opt/gradlew; \
	gradle wrapper; \
	./gradlew;

ENV PATH "/opt/gradlew:${PATH}"

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
		"build-tools;29.0.0" \
		"platforms;android-29" \
		"system-images;android-29;google_apis;x86_64" \
		"emulator";

RUN sdkmanager --update;

ENV PATH "/opt/android/sdk/emulator:${PATH}"
ENV PATH "/opt/android/sdk/platform-tools:${PATH}"
ENV PATH "/opt/android/sdk/build-tools/29.0.0:${PATH}"

COPY ./attachments/app-release.apk /
COPY ./flag.txt /
COPY ./setup_emulator.py /

RUN set -e -x; \
    chown -R user:user /home/user; \
    chmod 444 /app-release.apk /flag.txt; \
    chmod 555 /setup_emulator.py;
