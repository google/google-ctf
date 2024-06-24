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

; PORT_FROM_68K,               0x00
; .equ    PORT_YM2610_STATUS,          0x04
; .equ    PORT_PLAYBACK_FINISHED,      0x06
;; write ports
PORT_YM2610_A_ADDR              equ $04
PORT_YM2610_A_VALUE             equ $05
PORT_YM2610_B_ADDR              equ $06
PORT_YM2610_B_VALUE             equ $07
PORT_ENABLE_NMI                 equ $08
PORT_TO_68K                     equ $0c
PORT_DISABLE_NMI                equ $18