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

; Print the input flag.
PrintInputFlag:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.
    move.w          REG_VRAMADDR,-(sp)                              ; We need to save these values to the stack, because there's another function that can use them.
    move.w          REG_VRAMMOD,-(sp)

    move.w			#FIXMAP+(4*32)+8,REG_VRAMADDR      ; Set the address we want to start to print in the Fix Map.
	nop	                                                ; Safety pause for get everything loaded.
	move.w			#32,REG_VRAMMOD                     ; Increase 32 bytes after each write to VRAM, this coincides with the tile at the right.
    lea             INPUT_BUFFER,a0
    move.l          #31,d0        
.loop:
    clr.l           d1                                  ; Clear d1.
    move.b          (a0)+,d1
    addi.w          #$1100,d1

    ; Print that byte.
    move.w			d1,REG_VRAMRW               ; Write the tile to VRAM.
	nop        

    dbra			d0,.loop                    ; Loop back.

    move.w          (sp)+,REG_VRAMMOD
    move.w          (sp)+,REG_VRAMADDR
    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts

InitDecrypted:
    movem.l         d0/a0/a1,-(sp)

    lea             InitFlag,a0
    lea             INPUT_BUFFER,a1
    move.l          #32,d0
.loop:
    move.b          (a0)+,(a1)+
    dbra            d0,.loop

    movem.l         (sp)+,d0/a0/a1
    rts
