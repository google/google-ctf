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

; Entrypoint for the game.
;
; The game will first be a "start menu", after pressing start the user must select the
; challenge step they want to go to.
Game:
    jsr     PrintGoogleLogo                         ; Print the Google CTF logo.

; for (;;)
.hang:
    move.b	#0,REG_DIPSW	                        ; Kick watchdog
    jsr     .input                                  ; Input subroutine, to handle input events for this state.
    beq     .break
    jsr     WaitForVBLANK                           ; Wait for VBLANK
    bra     .hang

.break:
; Admin panel
    move.w  #1,REG_TIMERSTOP                        ; Stop the timer.
    
    ; Load timer no op.
    lea             TimerNop,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.


    move.b  #$ff,REG_SOUND                          ; Enable admin mode in Z80.
    move.w  #500,d0
.sound_wait:
    move.b	#0,REG_DIPSW
    nop
    dbra    d0,.sound_wait
    jsr     AdminGameMode                           ; Jump to admin panel.

    rts                                             ; Return from subroutine.

.input:
    ; Store the value of the input in the buffer.
    jsr             .mapInput
    jsr             .checkKonamiCode                ; Check if the input buffer has the konami code.
    rts

.mapInput:
    movem.l         d0/d1/a0/a1,-(sp)                        ; Push registers we use
    
    ; input = *BIOS_P1CHANGE
    ; if (P1CHANGE == 0) return;
    move.b          BIOS_P1CHANGE,d0
    cmp.b           #0,d0
    beq             .mapInputDone

    ; Push the array down.
    ; for (i = len(input_array)-1;i>0;i--)
    ;   input_array[i+1] = input_array[i]
    move.b          #9,d1                           ; Input array length is 10.
    lea             INPUT_ARRAY+9,a0
    lea             INPUT_ARRAY+10,a1
.mapInputLoop:
    cmpi.b          #0,d1                           
    ble             .mapInputLoopDone
    move.b          -(a0),-(a1)
    addi.b          #1,d1
    bra             .mapInputLoop

.mapInputLoopDone
    ; input_array[0] = input
    move.b          d0,(INPUT_ARRAY)                ; Store the value of the input.

.mapInputDone:
    movem.l         (sp)+,d0/d1/a0/a1                     ; Pop registers.
    rts                                             ; Return

.checkKonamiCode:
    movem.l         d0/a0/a1,-(sp)  ; Push to the stack.
    lea             INPUT_ARRAY,a0
    lea             Konami,a1
    move.l          #9,d0
.konami_loop:
    cmp.b       (a0)+,(a1)+
    bne         .konami_done
    dbra        d0,.konami_loop
    ; If we're here then the input matched.
    bra         .break
.konami_done:
    movem.l         (sp)+,d0/a0/a1  ; Pop from stack.
    rts

COIN_SOUND:
    movem.l         d0,-(sp)
    move.b          #4,REG_SOUND                            ; Play the coin sound.
    ; Wait for a bit.
    clr.l           d0
    move.w          #1000,d0
.loop:
    move.b	        #0,REG_DIPSW
    dbra            d0,.loop

    movem.l         (sp)+,d0
    rts

TimerNop:
    rts