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

PrintInsertCoin:
    movem.l d0/a0,-(sp)                             ; Push to the stack,
    lea     InsertCoin,a0                           ; Load the text we want to write.
    move.w  #FIXMAP+(14*32)+28,d0                   ; Print at the lower part of the screen.
    move.w  #$0000,d1                               ; Palette 0.
    ; Print "Insert Coin"
	jsr	    Print

    ; Load timer for half a second.
    lea     PrintCoinEmpty,a0
    move.l  a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w  #$2d,REG_TIMERHIGH           
    move.w  #$c6c0,REG_TIMERLOW

    movem.l (sp)+,d0/a0                             ; Restore from stack.
    rts

PrintCoinEmpty:
    movem.l d0/a0,-(sp)                             ; Push to the stack,
    lea     Empty,a0                                ; Load the text we want to write.
    move.w  #FIXMAP+(14*32)+28,d0                   ; Print at the lower part of the screen.
    move.w  #$0000,d1                               ; Palette 0.
    ; Print "Empty"
	jsr	    Print

    ; Load timer for half a second.
    lea     PrintInsertCoin,a0
    
    move.l  a0,TIMER_CALLBACK                       ; When timer interrupts, print the label.
    move.w  #$2d,REG_TIMERHIGH           
    move.w  #$c6c0,REG_TIMERLOW

    movem.l (sp)+,d0/a0                             ; Restore from stack.
    rts

PrintPressStart:
    movem.l d0/a0,-(sp)                             ; Push to the stack,
    lea     PressStart,a0                           ; Load the text we want to write.
    move.w  #FIXMAP+(14*32)+28,d0                   ; Print at the lower part of the screen.
    move.w  #$0000,d1                               ; Palette 0.
    ; Print "Press Start"
	jsr	    Print

    ; Load timer for half a second.
    lea     PrintStartEmpty,a0
    move.l  a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w  #$2d,REG_TIMERHIGH           
    move.w  #$c6c0,REG_TIMERLOW

    movem.l (sp)+,d0/a0                             ; Restore from stack.
    rts

PrintStartEmpty:
    movem.l d0/a0,-(sp)                             ; Push to the stack,
    lea     Empty,a0                                ; Load the text we want to write.
    move.w  #FIXMAP+(14*32)+28,d0                   ; Print at the lower part of the screen.
    move.w  #$0000,d1                               ; Palette 0.
    ; Print "Empty"
	jsr	    Print

    ; Load timer for half a second.
    lea     PrintPressStart,a0
    move.l  a0,TIMER_CALLBACK                       ; When timer interrupts, print the label.
    move.w  #$2d,REG_TIMERHIGH           
    move.w  #$c6c0,REG_TIMERLOW

    movem.l (sp)+,d0/a0                             ; Restore from stack.
    rts