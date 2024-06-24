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

; Clear all the sprites.
LSP_1ST:
    movem.l     d0,-(sp)                ; Push D0 to the stack.
    move.w      #SCB2,REG_VRAMADDR      ; Height attributes are in VRAM at Sprite Control Bank 2
    move.w      #1,REG_VRAMMOD          ; Set the VRAM address auto-increment value
    move.l      #512,d0                 ; Clear all 512 sprites
    nop                                 ; Safety pause.
; Clear all the sprites, we do this by writing $0000 to all the sprite bank.
.loop:
    move.w      #0,REG_VRAMRW           ; Write to VRAM.
    move.b	#0,REG_DIPSW		; Kick the watchdog.
    dbra        d0,.loop            	; Are we done ? No: jump back to .loop

    movem.l     (sp)+,d0		; Restore D0.
    rts					; Return from subroutine.

; Clear all the tiles in the fix layer.
; We do this by loading $FF (should be transparent).
FIX_CLEAR:
    movem.l     d0,-(sp)                ; Push D0 to the stack.
    move.l      #(40*32)-1,d0           ; Clear the whole map.
    move.w      #FIXMAP,REG_VRAMADDR    ; Start at FIXMAP and write the whole map.
    nop					; Safety pause.
.loop:
    move.w      #$00ff,REG_VRAMRW       ; Write to VRAM, tile $ff, palette 0 and bank 0.
    move.b	#0,REG_DIPSW		; Kick the watchdog.
    dbra        d0,.loop                ; Are we done ? No: jump back to .loop

    movem.l     (sp)+,d0                ; Restore D0.
    rts                                 ; Return from subroutine.

