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



all: ../attachments/bin.gz

../attachments/bin.gz: langton
	cp langton /tmp/bin
	gzip -f /tmp/bin
	cp /tmp/bin.gz ../attachments/bin.gz

langton: langton.c board.h
	time gcc langton.c -O3 -o langton
	time strip langton

board.h: gen_board.py
	time python3 gen_board.py board.h
