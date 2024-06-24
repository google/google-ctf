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

    ; https://wiki.neogeodev.org/index.php?title=68k_vector_table
    
; m68k Vector table.
; It's 64 long word vectors at the beginning of the ROM file.
; Upon reset this vector table is read.
; These vectors will change PC to whatever value is found here.
RAM_START               equ $10f300
PC_START                equ $C00402

    org $0
    dc.l        RAM_START               ; Initial value for Stack Pointer.
    dc.l        PC_START                ; Initial value for PC.
    dc.l        $00C00408               ; Bus error.
    dc.l        $00C0040E               ; Address error.
    dc.l        $00C0040E               ; Illegal instruction.
    dc.l        $0000034C               ; Division by zero.
    dc.l        $0000034E               ; CHK out of bounds.
    dc.l        $0000034E               ; TRAPV.
    dc.l        $00C0041A               ; Privilege violation. This never happens because we always use supervisor mode.
    dc.l        $00C00420               ; This will get executed after each instruction in TRACE mode. We don't need it.
    
    org $60
    dc.l        $00C00432               ; No ack from Hardware.

    org $64
    dc.l        VBLANK                  ; VBLANK.
    dc.l        TIMER_INTERRUPT         ; Timer interrupt.
    dc.l        $00C00426               ; Cold boot.

    ; There are more entries in the table, but we don't need those.

    ; https://wiki.neogeodev.org/index.php?title=68k_program_header
    org $100
    dc.b        "GCTF",$00              ; BIOS name.

    org $107
    dc.b        $00                     ; $00 for cartridge system.
    dc.w        $cafe                   ; NGH number, doesn't matter.

