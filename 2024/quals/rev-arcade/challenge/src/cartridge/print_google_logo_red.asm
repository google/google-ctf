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

; Print the Google logo.
; The Google logo is 15 tiles wide and 9 tiles tall.

RED_GAME_LOGO           equ 0                       ; The Google logo is the first sprite on the bank.
RED_GAME_LOGO_H         equ 9
RED_GAME_LOGO_W         equ 15
PALETTE2_NOMIRROR       equ $300

PrintGoogleLogoRed:
    movem.l     d0/d1/d6/d7,-(sp)               ; Push to the stack.
    move.w      #1,REG_VRAMMOD                  ; Increase 1 each write.

    clr.w       d0                              ; i = 0
.scb1_w_loop:                                   ; for (i=0; i<15; i++)
    cmpi.w      #RED_GAME_LOGO_W,d0                 ; Check if we reached the end, jump out if yes.
    bge         .scb1_w_done

    ; SCB1 + (i*64)
    move.w      d0,d7
    lsl.w       #6,d7
    addi.w      #SCB1,d7

    ; *REG_VRAM_ADDR = SCB1 + (i*64)
    move.w      d7,REG_VRAMADDR           
    nop

    clr.w       d1                              ; j = 0
    ; tile = START_TILE + i
    move.w      d0,d7
    addi.w      #RED_GAME_LOGO,d7
.scb1_h_loop:                                   ; for (j=0; j<9; i++)
    cmpi.w      #RED_GAME_LOGO_H,d1                 ; Check if we reached the end, jump out if yes.
    bge         .scb1_h_done

    move.w      d7,REG_VRAMRW                   ; Draw the tile to VRAM.
    nop

    move.w      #PALETTE2_NOMIRROR,REG_VRAMRW   ; Attributes: Palette 1, no mirror, no animation.
    nop

    addq.w      #1,d1                           ; j++
    ; tile += width
    addi.w      #RED_GAME_LOGO_W,d7
    bra         .scb1_h_loop

.scb1_h_done:
    addq.w      #1,d0                           ; i++
    bra         .scb1_w_loop

.scb1_w_done:

    ; Now we need to handle the rest of the banks.
    move.w      #$200,REG_VRAMMOD               ; SCB2, 3 and 4 are $200 bytes apart from each other.
    move.w      #SCB2,REG_VRAMADDR              ; Target first SCB2.
    nop

    move.w      #$fff,REG_VRAMRW                ; Shrinking coeficients, make them full size.
    nop

    ; VRAMMOD moved to SCB3 now.
    move.w      #($e400+RED_GAME_LOGO_H),REG_VRAMRW ; Y position, non-sticky, sprite height in tiles.
    nop

    ; VRAMMOD moved to SCB4 now.
    move.w      #$1400,REG_VRAMRW               ; X position.
    nop

    move.w       #1,d0                          ; i = 1
.scb2_loop:                                     ; for (i=1; i<15; i++)
    cmpi.w      #RED_GAME_LOGO_W,d0                 ; If we reached the end, branch out.
    bge         .scb2_done

    ; *REG_VRAMADDR = (SCB2 + i)
    move.w      d0,d1
    addi.w      #SCB2,d1
    move.w      d1,REG_VRAMADDR
    nop

    move.w      #$fff,REG_VRAMRW                ; Make it full size.
    nop

    move.w      #$40,REG_VRAMRW                 ; Sticky bit, so it tracks the parent tile.
    nop

    addq.w      #1,d0                           ; i++
    bra         .scb2_loop

.scb2_done
    movem.l (sp)+,d0/d1/d6/d7                   ; Pop from the stack.
    rts                                         ; Return from subroutine