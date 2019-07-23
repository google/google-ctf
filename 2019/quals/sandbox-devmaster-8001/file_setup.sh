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

############################
### NOTE TO COMPETITORS: ###
# This file only exists because of a quirk in our deployment infrastructure.
# You can safely ignore it.
############################

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd $DIR
find . -user 1337  | xargs -n1 -I{} chown root {}
find . -group 1337 | xargs -n1 -I{} chgrp root {}
chmod 6744 ./drop_privs

"${DIR}/${1}" "${@:2}"
