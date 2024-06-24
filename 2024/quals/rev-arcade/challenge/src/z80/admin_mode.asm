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

; The M68k is sending the key and flag, store it and increase counter.
AdminMode:
	pop			af				; A was saved from before, so restore it.
	push			hl				; We're going to use HL.
	push			af				; We're going to also use A.

	ld			a,(INPUT_COUNT)			; Load the contents of INPUT_COUNT.
	
	; This is essentially a<=32, but Z80 doesn't have that comparison.
	cp			32				; Compare 32 with the accumulator.
	jr			c,.rx_flag			; Jump if Carry flag is set, meaning a < 32.
	jr			z,.rx_flag			; Jump if Zero flag is set, meaning a = 32.
	
	; At this point we know this byte belongs to the key, so pop AF to get the byte.
	pop			af

	; Push all bytes of the key down 1 byte
	; Then put the new byte on top.
	call			PushKeyBuffer			; Push all bytes down in the array.
	ld			hl,KEY_RAM			; Load the location for the new byte.
	ld			(hl),a				; Load the byte to KEY_RAM.
	jp			.decrement			; Jump to decrement the counter by one.

; This subroutine handles receiving bytes for the flag in plaintext.
.rx_flag:
	pop			af				; Restore the byte that the m68k gave us.
	call			PushInputBuffer			; Push all bytes down.
	ld			hl,INPUT_BUFFER			; Load the location for the new byte.
	ld			(hl),a				; Load the value of the byte to INPUT_BUFFER.

; Decrement 1 on INPUT_COUNT.
.decrement:
	; Decrement 1 on the input count
	ld			hl,INPUT_COUNT			; Load the address of INPUT_COUNT.
	dec			(hl)				; Decrement the contents of INPUT_COUNT by 1.
	ld			a,(hl)				; Load the contents of INPUT_COUNT to the accumulator.
	cp			0				; Compare it with 0.
	jr			nz,.done			; If A != 0 then  we still need more key bytes, jump to .done so we keep waiting.

	; At this point we have all necessary bytes for the key, so encrypt.
	; This process is computationally expensive (you know, for the Z80) so the m68k should wait long enough to not interrupt us
	; while encryption happens.

	call			Encrypt				; Encrypt the flag.
	ld			a,$30				; Reset INPUT_COUNT to 16 (the key length) + 32 (the flag length) = $10 + $20 = $30.
	ld			(INPUT_COUNT),a			; Load the byte at address INPUT_COUNT.

	call			CheckMatch			; Call CheckMatch, this should output a sound for "correct" or "wrong".

; This subroutine pops everything we used from the stack and returns.
.done:
	pop			hl
	pop			ix
	pop			af
	retn

; This subroutine pushes 1 byte down for every byte in the key array.
PushKeyBuffer:
    push            		af				; We're going to use A.
    ld              		hl,KEY_RAM+15          		; Load the last byte of the array: hl = array[len(array)-1]
    ld              		de,KEY_RAM+14          		; Load the second to last byte of the array: de = array[len(array)-2]

; i -> last byte (hl)
; j -> second to last (de)
; b = 32
    ld              		b,16                        	; Load B with 16, so we loop 16 times.
.loop:
    ; array[i] = array[j]
    ld              		a,(de)                      	; Load the contents of DE in the accumulator.
    ld              		(hl),a                      	; Store the contents of DE into the memory referenced by hl.
    ; Move both pointers up the array, towards 0.
    dec             		hl
    dec             		de

    djnz            		.loop				; Decrement B and jump if it's not zero. 

    pop            		af				; Restore A.
    ret								; Return from subroutine.

; Push the buffer down for the flag input.
PushInputBuffer:
    push            		af
    ld              		hl,INPUT_BUFFER+31          	; Load the last byte of the array: hl = array[len(array)-1]
    ld              		de,INPUT_BUFFER+30          	; Load the second to last byte of the array: de = array[len(array)-2]

; i -> last byte (hl)
; j -> second to last (de)
; b = 32
    ld              		b,32                        	; Load B with 32, so we loop 32 times.
.loop:
    ; array[i] = array[j]
    ld              		a,(de)                      	; Load the contents of DE in the accumulator.
    ld              		(hl),a                      	; Store the contents of DE into the memory referenced by hl.
    ; Move both pointers up the array.
    dec             		hl
    dec             		de

    djnz            		.loop				; Decrement B and jump if it's not zero.

    pop            		af				; Restore A.
    ret								; Return from subroutine.

