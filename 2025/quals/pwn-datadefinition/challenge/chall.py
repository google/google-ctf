# Copyright 2025 Google LLC
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
import sys


def main():
    print('Do you like dd? It is my favorite old-style tool :D\n')
    line = input('  > What is your favorite dd line?: ').encode()
    user_input = input('  > Any input to go with it?: ').encode()
    print('I like it! Let\'s give it a go!')
    res = subprocess.run(['dd'] + line.split(), input=user_input,
        capture_output=True)
    print(res.stdout.decode('utf-8'))
    print(res.stderr.decode('utf-8'))
    print('It was fun, bye!')


if __name__ == '__main__':
    main()
