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
	pop				af						; A was saved before, so restore it.
	push			hl

	push			af
	ld				a,(INPUT_COUNT)
	cp				32
	jr				c,.rx_flag
	jr				z,.rx_flag
	pop				af

	; Push all bytes of the key down 1 byte
	; Then put the new byte on top.
	call			PushKeyBuffer			; Push all bytes down.
	ld				hl,KEY_RAM				; Load the new byte.
	ld				(hl),a
	jp				.decrement

.rx_flag:
	pop				af
	call			PushInputBuffer				; Push all bytes down.
	ld				hl,INPUT_BUFFER				; Load the new byte.
	ld				(hl),a

.decrement:
	; Decrement 1 on the input count
	ld				hl,INPUT_COUNT
	dec				(hl)
	ld				a,(hl)
	cp				0
	jr				nz,.done				; If we still need more key bytes, keep waiting.

	; At this point we have all necessary bytes for the key, so decrypt.

	call			Encrypt					; If we have the entire key, encrypt the flag.
	ld				a,$30
	ld				(INPUT_COUNT),a

	call			CheckMatch

.done:
	pop				hl
	pop				ix
	pop				af
	retn

PushKeyBuffer:
    push            af
    ld              hl,KEY_RAM+15          ; Load the last byte of the array: hl = array[len(array)-1]
    ld              de,KEY_RAM+14          ; Load the second to last byte of the array: de = array[len(array)-2]

; i -> last byte (hl)
; j -> second to last (de)
; b = 32
    ld              b,16                        ; Load B with 16, so we loop 16 times.
.loop:
    ; array[i] = array[j]
    ld              a,(de)                      ; Load the contents of DE in the accumulator.
    ld              (hl),a                      ; Store the contents of DE into the memory referenced by hl.
    ; Move both pointers up the array.
    dec             hl
    dec             de

    djnz            .loop

    pop            af
    ret

; Push the buffer down.
PushInputBuffer:
    push            af
    ld              hl,INPUT_BUFFER+31          ; Load the last byte of the array: hl = array[len(array)-1]
    ld              de,INPUT_BUFFER+30          ; Load the second to last byte of the array: de = array[len(array)-2]

; i -> last byte (hl)
; j -> second to last (de)
; b = 32
    ld              b,32                        ; Load B with 16, so we loop 16 times.
.loop:
    ; array[i] = array[j]
    ld              a,(de)                      ; Load the contents of DE in the accumulator.
    ld              (hl),a                      ; Store the contents of DE into the memory referenced by hl.
    ; Move both pointers up the array.
    dec             hl
    dec             de

    djnz            .loop

    pop            af
    ret