#!/bin/bash

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

docker build -t healthcheck .

echo "Starting healthcheck container at port 5000"
ENV=""
if [ -n "$ADDRESS" ]; then
  ENV="$ENV -e ADDRESS=$ADDRESS"
fi
if [ -n "$PORT" ]; then
  ENV="$ENV -e PORT=$PORT"
fi
exec docker run --rm -it -p 5000:5000 --net=host $ENV healthcheck
