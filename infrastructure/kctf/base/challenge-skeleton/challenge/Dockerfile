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
FROM kctf-nsjail

RUN apt-get -y update
RUN apt-get -y upgrade

RUN ln -s /secrets/flag /chroot/flag

COPY files /chroot/home/user

CMD /usr/bin/k8s_nsjail_setup.sh && exec setpriv --init-groups --reset-env --reuid user --regid user --inh-caps=-all -- /usr/bin/nsjail --config /config/nsjail.cfg
