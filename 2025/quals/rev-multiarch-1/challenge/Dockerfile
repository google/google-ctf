# Copyright 2025 Google LLC
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
FROM ubuntu:24.04 as chroot

# ubuntu24 includes the ubuntu user by default
RUN /usr/sbin/userdel -r ubuntu && /usr/sbin/useradd --no-create-home -u 1000 user

RUN apt-get -qq update && apt-get install -qq -y python3

COPY flag /
COPY multiarch /home/user/
COPY crackme.masm /home/user/
COPY runner.py /home/user/
RUN chmod +x /home/user/multiarch

FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
  kctf_drop_privs \
  socat \
  TCP-LISTEN:1337,reuseaddr,fork \
  EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /usr/bin/python3 /home/user/runner.py"
