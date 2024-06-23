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

BLINK_FLAG_LOCATION_BASE             equ FIXMAP+(4*32)+8

; Get the currently selected char and blink it
BlinkFlag:
    movem.l         d0-d2/a0,-(sp)                          ; Push to the stack.

    jsr             PrintInputFlag

     ; Load timer and callback.
    lea             BlinkFlagEmpty,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.

    movem.l (sp)+,d0-d2/a0                                  ; Restore from stack.
    rts

; Print an empty char on the selected cursor.
BlinkFlagEmpty:
    movem.l         d0/a0,-(sp)                          ; Push to the stack.
    move.w          REG_VRAMADDR,-(sp)                              ; We need to save these values to the stack, because there's another function that can use them.
    move.w          REG_VRAMMOD,-(sp)

    clr.l           d0
    move.b          BLINK_SELECTED,d0
    lsl.l           #5,d0                                   ; Multipy by 32
    addi.l          #BLINK_FLAG_LOCATION_BASE,d0

    move.w			d0,REG_VRAMADDR      ; Set the address we want to start to print in the Fix Map.
	nop	                                                    ; Safety pause for get everything loaded.

    move.w          #$11ff,d0

    ; Print that byte.
    move.w			d0,REG_VRAMRW               ; Write the tile to VRAM.
	nop                         		        ; Safety pause.
    
    ; Load timer and callback.
    lea             BlinkFlag,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.

    move.w          (sp)+,REG_VRAMMOD
    move.w          (sp)+,REG_VRAMADDR
    movem.l         (sp)+,d0/a0                                  ; Restore from stack.
    rts

