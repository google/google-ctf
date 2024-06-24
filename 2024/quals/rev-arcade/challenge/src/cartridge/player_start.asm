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

PLAYER_START:
    move.b      #1,REG_TIMERSTOP
    move.b      #2,BIOS_USER_MODE                   ; Tell the BIOS that the game started.
    jsr         SYS_LSP_1ST
    jsr         SYS_FIX_CLEAR
    move.w      #BLACK,BACKDROP                  ; Change background to midgreen.

    ; Load the background sprite.
    jsr         .printPlayer1Start

    ; Load timer with the callback.
    lea         .startGame,a0
    move.l      a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w      #$8d,REG_TIMERHIGH           
    move.w      #$c6c0,REG_TIMERLOW

.hang:
    move.b	    #0,REG_DIPSW
    bra         .hang

.printPlayer1Start:
    movem.l     d0/a0,-(sp)                             ; Push to the stack,
    lea         Player1Start,a0                           ; Load the text we want to write.
    move.w      #FIXMAP+(11*32)+14,d0                   ; Print in the middle of the screen.
    move.w      #$0000,d1                               ; Palette 8.
    ; Print "Player 1 start"
	jsr	        Print

    movem.l (sp)+,d0/a0                             ; Restore from stack.
    rts

.startGame:
    move.w	    #2,REG_IRQACK                       ; Acknowledge the interrupt.
    move.w      #$2000,sr                           ; Re-enable all interrupts.
    jmp         StartGame