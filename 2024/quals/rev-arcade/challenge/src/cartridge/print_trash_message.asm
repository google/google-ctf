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

; Print a message that says "there's only trash in here".

; TODO update
TRASH_MSG           equ 557                     ; Sprite location is previous sprite + all sprites (H x W). 
TRASH_MSG_OFFSET    equ 31                      ; Offset is the previous offset + previous H.
TRASH_MSG_H         equ 2
TRASH_MSG_W         equ 8
TRASH_MSG_Y         equ $33c
TRASH_MSG_X         equ $60
PALETTE7_NOMIRROR   equ $700

PrintTrashMessage:
    movem.l     d0/d1/d6/d7,-(sp)               ; Push to the stack.
    move.w      #1,REG_VRAMMOD                  ; Increase 1 each write.

    clr.w       d0                              ; i = 0
.scb1_w_loop:                                   ; for (i=0; i<15; i++)
    cmpi.w      #TRASH_MSG_W,d0                 ; Check if we reached the end, jump out if yes.
    bge         .scb1_w_done

    ; SCB1 + (i*64)
    move.w      d0,d7
    addi.w      #TRASH_MSG_OFFSET,d7
    lsl.w       #6,d7
    addi.w      #SCB1,d7

    ; *REG_VRAM_ADDR = SCB1 + (i*64)
    move.w      d7,REG_VRAMADDR
    nop

    clr.w       d1                              ; j = 0
    ; tile = START_TILE + i
    move.w      d0,d7
    addi.w      #TRASH_MSG,d7
.scb1_h_loop:                                   ; for (j=0; j<9; i++)
    cmpi.w      #TRASH_MSG_H,d1                 ; Check if we reached the end, jump out if yes.
    bge         .scb1_h_done

    move.w      d7,REG_VRAMRW                   ; Draw the tile to VRAM.
    nop

    move.w      #PALETTE7_NOMIRROR,REG_VRAMRW   ; Attributes: Palette 3, no mirror, no animation.
    nop

    addq.w      #1,d1                           ; j++
    ; tile += width
    addi.w      #TRASH_MSG_W,d7
    bra         .scb1_h_loop

.scb1_h_done:
    addq.w      #1,d0                           ; i++
    bra         .scb1_w_loop

.scb1_w_done:

    ; Now we need to handle the rest of the banks.
    move.w      #$200,REG_VRAMMOD               ; SCB2, 3 and 4 are $200 bytes apart from each other.
    move.w      #(SCB2+TRASH_MSG_OFFSET),REG_VRAMADDR              ; Target first SCB2.
    nop

    move.w      #$fff,REG_VRAMRW                ; Shrinking coeficients, make them full size.
    nop

    ; VRAMMOD moved to SCB3 now.
    move.w      #TRASH_MSG_Y,d0
    lsl.w       #7,d0
    addi.w      #TRASH_MSG_H,d0
    move.w      d0,REG_VRAMRW ; Y position, non-sticky, sprite height in tiles.
    nop

    ; VRAMMOD moved to SCB4 now.
    move.w      #(TRASH_MSG_X<<7),REG_VRAMRW               ; X position.
    nop

    move.w       #1,d0                          ; i = 1
.scb2_loop:                                     ; for (i=1; i<15; i++)
    cmpi.w      #TRASH_MSG_W,d0                 ; If we reached the end, branch out.
    bge         .scb2_done

    ; *REG_VRAMADDR = (SCB2 + i)
    move.w      d0,d1
    addi.w      #(SCB2+TRASH_MSG_OFFSET),d1
    move.w      d1,REG_VRAMADDR
    nop

    move.w      #$fff,REG_VRAMRW                ; Make it full size.
    nop

    move.w      #$40,REG_VRAMRW                 ; Sticky bit, so it tracks the parent tile.
    nop

    addq.w      #1,d0                           ; i++
    bra         .scb2_loop

.scb2_done:
    lea     RemoveTrashMessage,a0
    move.l  a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w  #$6d,REG_TIMERHIGH           
    move.w  #$c6c0,REG_TIMERLOW

    movem.l (sp)+,d0/d1/d6/d7                   ; Pop from the stack.
    rts                                         ; Return from subroutine

RemoveTrashMessage:
    move.w      #(SCB2+TRASH_MSG_OFFSET),REG_VRAMADDR              ; Target first SCB2.
    nop

    move.w      #0,REG_VRAMRW                ; Make it small to disappear.
    nop
    rts