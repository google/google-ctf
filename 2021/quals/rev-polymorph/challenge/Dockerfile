# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM ubuntu:20.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

#COPY flag /

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/
COPY autograder /home/user/
#COPY autograder_in_jail /chroot/home/user/autograder_in_jail
COPY expected_public_map /home/user/expected_public_map
COPY expected_map /home/user/expected_map
COPY expected_super_secret_map /home/user/expected_super_secret_map
#RUN mkdir /chroot/home/user/test_cases
COPY public/safe/ /home/user/test_cases
COPY public/malware/ /home/user/test_cases
COPY private/safe/ /home/user/test_cases
COPY private/malware/ /home/user/test_cases
COPY super_private/safe/ /home/user/test_cases
COPY super_private/malware/ /home/user/test_cases
COPY pow.py /kctf/pow.py
COPY flag /home/user/flag
#RUN touch /chroot/home/user/antivirus
RUN mkdir /chroot/home/user
RUN chmod -R 777 /home/user

RUN ln -s `which python3` /usr/bin/python
RUN ln -s `which python3` /usr/bin/python38
RUN ln -s `which python3` /usr/bin/python385

CMD kctf_setup && \
    mount -t tmpfs tmpfs /tmp && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow /home/user/autograder"
