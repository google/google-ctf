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

; Prints the content of the key to screen.
PrintKey:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.
    move.w          REG_VRAMADDR,-(sp)                              ; We need to save these values to the stack, because there's another function that can use them.
    move.w          REG_VRAMMOD,-(sp)

    move.w			#FIXMAP+(4*32)+23,REG_VRAMADDR      ; Set the address we want to start to print in the Fix Map.
	nop	                                                ; Safety pause for get everything loaded.
	move.w			#32,REG_VRAMMOD                     ; Increase 32 bytes after each write to VRAM, this coincides with the tile at the right.
    lea             KEY_LOCATION,a0
    move.l          #15,d0        
.loop:
    clr.l           d1                                  ; Clear d1.
	move.b			(a0),d1             ; Move the contents of A0.
	
    ; We need to take the first half of the byte, print that, then get the second half of the byte, and print that.
    andi.b          #$f0,d1
    lsr.b           #4,d1
    addi.w          #$1200,d1

    ; Print that byte.
    move.w			d1,REG_VRAMRW               ; Write the tile to VRAM.
	nop                         		        ; Safety pause.
	
    clr.l           d1
    move.b          (a0)+,d1
    andi.b          #$0f,d1
    addi.w          #$1200,d1

    ; Print that byte.
    move.w			d1,REG_VRAMRW               ; Write the tile to VRAM.
	nop        

    dbra			d0,.loop                    ; Loop back.

    move.w          (sp)+,REG_VRAMMOD
    move.w          (sp)+,REG_VRAMADDR
    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts                                                     ; Return from subroutine.