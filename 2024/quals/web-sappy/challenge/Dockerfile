# Copyright 2024 Google LLC
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
FROM node@sha256:162d92c5f1467ad877bf6d8a098d9b04d7303879017a2f3644bfb1de1fc88ff0 AS closure
WORKDIR /closure/
RUN npm install google-closure-compiler@20240317.0.0 google-closure-library@20230802.0.0
COPY src/sap.js /closure/
RUN npx google-closure-compiler --js=sap.js --js node_modules/google-closure-library/**/*.js \
                            --dependency_mode=PRUNE --entry_point=goog:sap  \
                            --js_output_file=sap-compiled.js

FROM node:20-slim AS chroot
WORKDIR /home/app/
COPY src/package.json src/package-lock.json /home/app/
RUN npm ci --omit=dev
COPY src/ /home/app/
COPY --from=closure /closure/sap-compiled.js /home/app/public/static/sap.js
RUN chmod -R a+r /home/app/

FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

COPY --from=chroot / /chroot
COPY ./nsjail.cfg /nsjail.cfg
COPY ./nsjail_entrypoint.sh /chroot/nsjail_entrypoint.sh
COPY ./run.sh /run.sh

CMD /run.sh