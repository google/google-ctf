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

if [[ "$(id -u)" != "0" ]]; then
  echo -e "Challenge must be run as root."
  exit 1
fi

if [[ "$(capsh --print)" != *"cap_sys_admin"* ]]; then
  echo -e "Challenge must have the CAP_SYS_ADMIN capability."
  exit 1
fi

if [[ "$(capsh --print)" != *"cap_sys_ptrace"* ]]; then
  echo -e "Challenge must have the CAP_SYS_PTRACE capability."
  exit 1
fi

PTRACE_SCOPE="0"
if [[ -f "/proc/sys/kernel/yama/ptrace_scope" ]]; then
  PTRACE_SCOPE="$(cat /proc/sys/kernel/yama/ptrace_scope)"
fi

if [[ "$PTRACE_SCOPE" != "0" ]]; then
  # Before bailing, see if we can disable it within the Docker container
  echo "0" > /proc/sys/kernel/yama/ptrace_scope
fi


if [[ "$PTRACE_SCOPE" != "0" ]]; then
  echo -e "Challenge requires Yama ptrace scope to be disabled."
  exit 1
fi


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Start the admin build
"$DIR/target_loop.sh" & 2>/dev/null >/dev/null </dev/null

cat | "$DIR/server"

