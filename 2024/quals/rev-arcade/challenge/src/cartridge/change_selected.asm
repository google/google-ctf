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

UpdateSelectedValue:
    movem.l         d0-d2/a0,-(sp)

    clr.l           d1
    move.b          BLINK_SELECTED,d1
    lea             KEY_LOCATION,a0
    move.b          BIOS_P1CHANGE,d0
    btst.l          #0,d0                       ; Check if it's up.
    bne             .up
    btst.l          #1,d0                       ; Check if it's down.
    bne             .down
    bra             .done

.up:
    move.b          #1,d2
    lsr.b           #1,d1                       ; Divide by 2.
    add.l           d1,a0
    move.b          BLINK_SELECTED,d1
    btst.l          #0,d1
    bne             .up_odd
    bra             .up_even

.up_even:
    move.b          (a0),d2
    move.b          (a0),d0
    andi.b          #$0f,d0
    addi.b          #$10,d2
    andi.b          #$f0,d2
    add.b           d2,d0
    move.b          d0,(a0)
    bra             .done
.up_odd:
    move.b          (a0),d2
    move.b          (a0),d0
    andi.b          #$f0,d0
    addi.b          #1,d2
    andi.b          #$0f,d2
    add.b           d2,d0
    move.b          d0,(a0)
    bra             .done

.down:
    move.b          #1,d2
    lsr.b           #1,d1                       ; Divide by 2.
    add.l           d1,a0
    move.b          BLINK_SELECTED,d1
    btst.l          #0,d1
    bne             .down_odd
    bra             .down_even

.down_even:
    move.b          (a0),d0
    move.b          (a0),d2
    andi.b          #$0f,d0
    subi.b          #$10,d2
    andi.b          #$f0,d2
    add.b           d2,d0
    move.b          d0,(a0)
    bra             .done
.down_odd:
    move.b          (a0),d2
    move.b          (a0),d0
    andi.b          #$f0,d0
    subi.b          #1,d2
    andi.b          #$0f,d2
    add.b           d2,d0
    move.b          d0,(a0)
    bra             .done

.done:
    movem.l         (sp)+,d0-d2/a0
    rts
