# Copyright 2021 Google LLC
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

import subprocess
import tempfile
import sys
import shutil
import os
import base64

os.symlink('/usr/lib/chromium/mojo_bindings', '/tmp/exploit/mojo')

subprocess.check_call(['/usr/lib/chromium/chrome', '--headless', '--disable-gpu',
                       '--remote-debugging-port=9222', '--user-data-dir=/tmp/userdata',
                       '--enable-logging=stderr', 'exploit.html'], cwd='/tmp/exploit')
