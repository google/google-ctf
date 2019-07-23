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

(cd src && bazel build -c opt :all && bazel build -c opt //third_party:all) &&
  mkdir -p built_bins &&
  sudo cp src/bazel-bin/admin built_bins/ &&
  sudo cp src/bazel-bin/drop_privs built_bins/ &&
  sudo cp src/bazel-bin/executor built_bins/ &&
  sudo cp src/bazel-bin/third_party/linux-sandbox built_bins/ &&
  sudo cp src/bazel-bin/server built_bins/ &&
  sudo cp src/bazel-bin/admin_builder_client built_bins/ &&
  sudo cp src/bazel-bin/client built_bins/ &&
  sudo cp src/bazel-bin/multiplexer built_bins/ &&
  sudo docker build -t sandbox-container-8001 .
