# Copyright 2022 Google LLC
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

set -x
set -e

./flag_encoder.py

gcc -fno-stack-protector -fcf-protection=none -o charset_check charset_check.c
./charset_check

echo 'char serial[] = "CTF{H0p3_y0u_l1k3_3LF_m4g1c}";' > serial.c
gcc -shared -o libserial.so serial.c

gcc -Wall -no-pie -o main main.c -Wl,-rpath=. -L. -lserial
./inject_relocations.py

chmod u+x eldar
./eldar

echo 'char serial[] = "CTF{H0p3_y0u_l1k3_3LF_m4g1d}";' > serial.c
gcc -shared -o libserial.so serial.c
./eldar

echo 'char serial[] = "CTF{H0p3_y0u_l1kJjN848qEGXc}";' > serial.c
gcc -shared -o libserial.so serial.c
./eldar

cp eldar Makefile ../attachments
echo 'char serial[] = "";' > ../attachments/serial.c
