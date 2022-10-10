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
FROM ubuntu:20.04 as inner_chroot

COPY init /bin/

FROM ubuntu:20.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user
COPY --from=inner_chroot / /home/user/chroot

RUN apt-get update && apt-get install -yq --no-install-recommends libprotobuf17

COPY flag /
RUN chown 1000:1000 /flag && chmod 0400 /flag
COPY chal /home/user/

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

COPY --from=chroot / /chroot

RUN apt-get update && apt-get install -yq --no-install-recommends uidmap
COPY subuid /etc/

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/chal"
