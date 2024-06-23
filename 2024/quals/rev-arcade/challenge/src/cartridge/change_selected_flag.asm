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

UpdateFlagSelectedValue:
    movem.l         d0-d2/a0,-(sp)

    clr.l           d1
    move.b          BLINK_SELECTED,d1
    lea             INPUT_BUFFER,a0
    move.b          BIOS_P1CHANGE,d0
    add.l           d1,a0
    btst.l          #0,d0                       ; Check if it's up.
    bne             .up
    btst.l          #1,d0                       ; Check if it's down.
    bne             .down
    bra             .done

    dc.l $deadbeef

.up:
    addi.b           #1,(a0)
    bra              .done

.down:
    subi.b           #1,(a0)

.done:
    movem.l         (sp)+,d0-d2/a0
    rts
