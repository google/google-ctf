; Copyright 2024 Google LLC
; 
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
; 
;     https://www.apache.org/licenses/LICENSE-2.0
; 
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.

ADMIN_MODE_ON					equ $F800
INPUT_COUNT                     equ ADMIN_MODE_ON + 1           ; Location of the input buffer count.
OUTPUT_COUNT                    equ INPUT_COUNT + 1

ENCRYPTED_BUFFER                equ ADMIN_MODE_ON + $20
INPUT_BUFFER                    equ ENCRYPTED_BUFFER + $20
SUM_RAM                         equ INPUT_BUFFER + $20
KEY_RAM                 		equ SUM_RAM + $10                ; Location of the key in RAM. $fe50

KEY0                            equ KEY_RAM
KEY1                            equ KEY0 + 4
KEY2                            equ KEY1 + 4
KEY3                            equ KEY2 + 4

V0_RAM                          equ KEY3 + 4
V1_RAM                          equ V0_RAM + 4

A_RAM                           equ V1_RAM + 4
B_RAM                           equ A_RAM + 4
C_RAM                           equ B_RAM + 4
ONE                             equ C_RAM + 4
