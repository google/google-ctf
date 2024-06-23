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

BLINK_SELECTED                  equ RAMSTART+30
BLINK_LOCATION_BASE             equ FIXMAP+(4*32)+23

; Get the currently selected char and blink it
BlinkKey:
    movem.l         d0-d2/a0,-(sp)                          ; Push to the stack.

    jsr             PrintKey

     ; Load timer and callback.
    lea             BlinkEmpty,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.

    movem.l (sp)+,d0-d2/a0                                  ; Restore from stack.
    rts

; Print an empty char on the selected cursor.
BlinkEmpty:
    movem.l         d0/a0,-(sp)                          ; Push to the stack.
    move.w          REG_VRAMADDR,-(sp)                              ; We need to save these values to the stack, because there's another function that can use them.
    move.w          REG_VRAMMOD,-(sp)

    clr.l           d0
    move.b          BLINK_SELECTED,d0
    lsl.l           #5,d0                                   ; Multipy by 32
    addi.l          #BLINK_LOCATION_BASE,d0

    move.w			d0,REG_VRAMADDR      ; Set the address we want to start to print in the Fix Map.
	nop	                                                    ; Safety pause for get everything loaded.

    move.w          #$10ff,d0

    ; Print that byte.
    move.w			d0,REG_VRAMRW               ; Write the tile to VRAM.
	nop                         		        ; Safety pause.
    
    ; Load timer and callback.
    lea             BlinkKey,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.

    move.w          (sp)+,REG_VRAMMOD
    move.w          (sp)+,REG_VRAMADDR
    movem.l (sp)+,d0/a0                                  ; Restore from stack.
    rts

; Subroutine to update BLINK_SELECTED based on input.
UpdateSelectedLocation:
    movem.l         d0/d1,-(sp)

    clr.l           d1
    move.b          BLINK_SELECTED,d1
    move.b          BIOS_P1CHANGE,d0
    btst.l          #3,d0                       ; Check if it's right.
    bne             .right
    btst.l          #2,d0                       ; Check if it's left.
    bne             .left
    bra             .done

.right:
    ; Don't update if we're at the end.
    cmpi.b          #31,d1
    bge             .done

    addi.b          #1,d1
    move.b          d1,BLINK_SELECTED
    bra             .done
.left:
    ; Don't update if we're at the beginning.
    tst.b           d1
    ble             .done

    subi.b          #1,d1
    move.b          d1,BLINK_SELECTED

.done:
    movem.l         (sp)+,d0/d1
    rts
