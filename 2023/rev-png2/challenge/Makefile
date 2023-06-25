# Copyright 2023 Google LLC
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



all: ../attachments/png2 ../attachments/flag.png2

png2-full: png2.c crc.inc
	gcc -O3 -o png2-full png2.c -DFULLSIZE -lz -lm

../attachments/png2: png2.c crc.inc
	gcc -O3 -o ../attachments/png2 png2.c -lz -lm
	strip ../attachments/png2

flag.ppm: flag.png
	convert flag.png -compress none flag.ppm

../attachments/flag.png2: flag.ppm png2-full
	./png2-full encode flag.ppm ../attachments/flag.png2

solve: decrypt.py ../attachments/flag.png2
	python3 decrypt.py ../attachments/flag.png2 /tmp/decrypted.png
	xdg-open /tmp/decrypted.png
