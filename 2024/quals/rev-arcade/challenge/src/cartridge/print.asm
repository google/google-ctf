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

; Prints characters from SROM bank 0 until $00 is read.
; Use A0 to point to the first byte to print.
; Use D0 to point where in the Fix Map should we print the first character.
; Use D1 for the palette.
Print:
	move.w			d0,REG_VRAMADDR     ; Set the address we want to start to print in the Fix Map.
	nop	                        ; Safety pause for get everything loaded.
	move.w			#32,REG_VRAMMOD     ; Increase 32 bytes after each write to VRAM, this coincides with the tile at the right.
.loop:
	move.b			(a0)+,d1            ; Move the contents of A0 (and move one byte) to D0.
	tst.b			d1 	                ; Check if we're dealing with $00.
	beq				.done		        ; Yes: We're done. No: Keep going.
	move.w			d1,REG_VRAMRW       ; Write the tile to VRAM.
	nop                         		; Safety pause.
	bra				.loop                   ; Loop back.
.done:
	rts                         ; Return from subroutine.