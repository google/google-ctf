#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Ian Eldred Pudney

set -e

rm -rf attachments
rm -rf /tmp/attachments_temp
mkdir /tmp/attachments_temp
cp -rf ./* /tmp/attachments_temp
mv /tmp/attachments_temp attachments

rm -rf attachments/healthcheck
rm -rf attachments/metadata.json
rm -rf attachments/attachments
rm -rf attachments/build_attachments.sh
rm -rf attachments/flag
rm -rf attachments/password
rm -rf attachments/src/exploit
rm -rf attachments/src/bazel-*
rm -rf attachments/Dockerfile
rm -rf attachments/nsjail_setup.sh
rm -rf attachments/file_setup.sh
mv attachments/attachments_Dockerfile attachments/Dockerfile
