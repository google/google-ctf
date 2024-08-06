# Copyright 2019 Google LLC
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
FROM alpine:latest
LABEL maintainer="Francisco Ribeiro <franciscogtr@google.com>"
RUN apk --update add --no-cache ca-certificates

#FROM scratch
#ENV PATH=/bin
#COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN /sbin/apk add readline-dev busybox upx

RUN mkdir /srv/challenge_setup
RUN mkdir /challenge
COPY README.flag /srv/challenge_setup
COPY ORME.flag /srv/challenge_setup
COPY setup_disclaimer /srv/challenge_setup/this_directory_is_not_part_of_the_challenge
COPY group /etc/
COPY passwd /etc/passwd

RUN /bin/chown -R 1337:1337 /srv/challenge_setup
RUN /bin/chmod 500 /srv/challenge_setup
RUN /bin/chmod 400 /srv/challenge_setup/README.flag /srv/challenge_setup/ORME.flag /srv/challenge_setup/this_directory_is_not_part_of_the_challenge

COPY shell /bin/shell
ENV USER login
RUN /bin/chown 1338:1338 /bin/shell
RUN /bin/chmod 04555 /bin/shell
WORKDIR /bin
RUN rm -f chmod cp mv link ln linux32 linux64 base64 cat dd ed egrep grep fgrep gunzip gzip more sed zcat rev su fatattr kbd_mode  bbconfig touch
WORKDIR /usr/bin
RUN rm -f hd tac uudecode uuencode less cmp head awk bunzip2 comm uniq sort traceroute nc hexdump xxd od xargs strings tr tee tail diff wget vi bzcat bzip2 cut find dumpleases xzcat ssl_client pscan nl whois traceroute6 unzip paste expand unexpand
WORKDIR /usr/sbin
RUN rm -f add-shell arping ether-wake sendmail remove-shell

RUN rm -f /bin/sh /bin/ash
WORKDIR /challenge

#RUN chmod 000 /challenge/ORME.flag
#ENTRYPOINT [ "/srv/challenge_setup/sh" ]
