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

; BIOS RAM locations
BIOS_MVS_FLAG               equ $10FD82
BIOS_SYSTEM_MODE            equ $10FD80
BIOS_STATCURNT              equ $10FDAC
BIOS_STATCHANGE             equ $10FDAD
BIOS_STATCURNT_RAW          equ $10FEDC
BIOS_STATCHANGE_RAW         equ $10FEDD
BIOS_USER_REQUEST           equ $10FDAE
BIOS_USER_MODE              equ $10FDAF
BIOS_CREDIT_DEC1            equ $10FDB0
BIOS_P1CURRENT              equ $10FD96
BIOS_P1PREVIOUS             equ $10FD95
BIOS_P1CHANGE               equ $10FD97
BIOS_START_FLAG             equ $10FDB4

; Registers
REG_SWPROM                  equ $3A0013
REG_LSPCMODE                equ $3C0006
REG_IRQACK                  equ $3C000C
REG_CRTFIX                  equ $3A001B
REG_DIPSW                   equ $300001
REG_STATUS_A                equ $320001
REG_STATUS_B                equ $380000
REG_P1CNT                   equ $300000
REG_VRAMADDR                equ $3C0000
REG_VRAMRW                  equ $3C0002
REG_VRAMMOD                 equ $3C0004

; Interesting places
COIN_SOUND                  equ $134
PLAYER_START                equ $128

; BRAM
P1_CREDITS_BCD              equ $D00034

; VRAM
SCB2                        equ $8000
FIXMAP                      equ $7000