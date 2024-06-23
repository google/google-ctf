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

; Z80 sound driver.

MVOL							equ $3f
CVOL							equ	$c0+$1f

; Sounds
COIN							equ $0000

    include "src/z80/regdefs.asm"
	include "src/z80/ym_regdefs.asm"
	include "src/z80/encrypted_flag.asm"
	include "src/z80/memory.asm"


; RESET - Start of program.
    org $00
Reset:
	ld				sp,$ffff			; Reset the stack pointer to the end of RAM.
	out				($08),a				; Enable NMI.
	xor				a					; Clear A.
	ld				(ADMIN_MODE_ON),a	; Clear the Admin Mode.
	ld				a,0
	ld				(ONE),a
	ld				(ONE+1),a
	ld				(ONE+2),a
	ld				a,1
	ld				(ONE+3),a
	ld				a,$30
	ld				(INPUT_COUNT),a		; Init INPUT_COUNT.
; Hang in RAM until NMI happens. 
.loop:
	jr	.loop

	; NMI from YM2610, just ignore.
	org	$38
	retn

	; Calls from the m68k.
	; The CPU NMI will drop the next instruction and put 66h in PC.
	; NMI for Z80 means that the M68k sent us a message.
	;
	; For each byte that is sent we need to:
	; * Store it in an input buffer (32 bytes long)
	; * Re-run the encryption with the new buffer.
	; * If the encrypted flag matches, play a "success!" music.
	; * If the encrypted flag doesn't match, play a "fail!" music.
	; The sound should tell the user when the Z80 is done with their input, so they can try the next one.
    org $66
	; We might be interrupting some other work, so save state.
	push			af
	push			ix

	in				a,($00)				; Read the command.
	push			af					; Save it to the stack.
	xor				a					; Clear A.
	ld				ix,ADMIN_MODE_ON	; Load the Admin Mode byte.
	cp				(ix)				
	jr				nz,JumpToAdminMode		; If Admin mode is not zero, that means it's enabled. Jump to handle Admin commands.
	
	; The following is a normal operation of a sound driver.
	pop				af					; Restore A.

	; $01 -> System ROM calls it when it's about to swap the driver for the cartdrige one.
	cp				$01
	jr				z,.prepareSwitch

	; $03 -> Reset. We should blindly jump to Reset and clear everything up.
	cp				$03
	jr				z,Reset

	; $04 -> Play a coin sound.
	cp				$04
	jr				z,PlayCoinSound

	; $ff -> Call to Admin Mode. This sets ADMIN_MODE_ON to $01, making the Z80 interpret any following byte as encryption bytes.
	cp				$ff
	jr				z,.enableAdminMode

	pop				ix
	pop				af
	retn								; Return from NMI.

; Called right before swapping the sound driver, we should Reset and report back setting bit 7.
; We don't care to pop anything from stack, since we're going to reset anyways.
.prepareSwitch:
	set				7,a						; Set bit 7 so the m68k knows we are working.
	out				($0C),a					; Send byte to out port.
	jp				Reset					; Blindly jump to Reset.

; Called by the game when it entered Admin mode.
; This makes the Z80 interpret the bytes for encryption rather than sound to play.
.enableAdminMode:
	ld				ix,ADMIN_MODE_ON		; Load the Admin Mode address.
	ld				(ix),1					; Load $01 to the address.

	pop				ix
	pop				af
	retn								; Return from NMI.

; Port A
; Handles the writes to PortA, both addr and value ports.
; DE is used for <attribute, value> pair.
WritePortA:
	di									; Disable maskable interrupts, although we don't use them.
	push	af							; Push the content of A.

	ld		a,d							; Load the value of D.
	out		(PORT_YM2610_A_ADDR),a		; Write the byte of the address port.

	; At lesat 6 NOPs to wait for this to go through.
	ld		b,6
.addr_loop:
	nop
	djnz	.addr_loop

	ld		a,e							; Load the value of E.
	out		(PORT_YM2610_A_VALUE),a		; Write the byte of the value.

	; At least 19 NOPs.
	ld		b,19
.value_loop:
	nop
	djnz	.value_loop

	pop	af								; Restore A.
	ei									; Enable maskable interrupts.
	ret									; Return from SP.

; Write to port B.
; d -> attribute
; e	-> value
WritePortB:
	di									; Disable maskable interrupts.
	push	af							; Save A.

	ld		a,d							; Load the attribute.
	out		(PORT_YM2610_B_ADDR),a		; Write it to Port B attribute.

	; At lesat 6 NOPs to wait for this to go through.
	ld		b,6
.addr_loop:
	nop
	djnz	.addr_loop

	ld		a,e							; Load the value.
	out		(PORT_YM2610_B_VALUE),a		; Write to Port B value.

	; At least 19 NOPs.
	ld		b,19
.value_loop:
	nop
	djnz	.value_loop

	pop		af							; Restore A
	ei
	ret

; In this mode the Z80 handles incoming bytes for encryption.
JumpToAdminMode:
	jp		AdminMode

PlayCoinSound:
	push		de
	; Set coarse tune on CH A
	ld			de,$01<<8 +$01
	call			WritePortA

	; Set fine tune on CH A
	ld			de,$00<<8 +$38
	call			WritePortA

	; Set CH A volume with envelope.
	ld			de,$08<<8 +$1f
	call			WritePortA

	; Set coarse EG time
	ld			de,$0c<<8 +$0e
	call			WritePortA

	; Set EG
	ld			de,$0d<<8 +$09
	call			WritePortA

	; Enable CH A.
	ld			de,$07<<8 +$fe
	call			WritePortA

	pop			de
	pop				ix
	pop				af
	ret

; Sound for a correct guess.
PlayCorrect:
	push		de
	; Set coarse tune on CH A
	ld			de,$01<<8 +$01
	call			WritePortA

	; Set fine tune on CH A
	ld			de,$00<<8 +$38
	call			WritePortA

	; Set CH A volume with envelope.
	ld			de,$08<<8 +$1f
	call			WritePortA

	; Set coarse EG time
	ld			de,$0c<<8 +$b0
	call			WritePortA

	; Set EG
	ld			de,$0d<<8 +$09
	call			WritePortA

	; Enable CH A.
	ld			de,$07<<8 +$fe
	call			WritePortA

	pop			de
	ret

; Sound for an incorrect guess.
PlayWrong:
	push		de
	; Set coarse tune on CH A
	ld			de,$01<<8 +$08
	call			WritePortA

	; Set fine tune on CH A
	ld			de,$00<<8 +$38
	call			WritePortA

	; Set CH A volume with envelope.
	ld			de,$08<<8 +$1f
	call			WritePortA

	; Set coarse EG time
	ld			de,$0c<<8 +$0e
	call			WritePortA

	; Set EG
	ld			de,$0d<<8 +$09
	call			WritePortA

	; Enable CH A.
	ld			de,$07<<8 +$fe
	call			WritePortA

	pop			de
	ret

; https://wiki.neogeodev.org/index.php?title=Playing_sound_samples
PlaySample:
	; https://wiki.neogeodev.org/index.php?title=YM2610_registers
	
	; Set the master volume to max.
	ld			de,PA_MVOL<<8 +MVOL
	call		WritePortB

	; Set Channel 1 volume to max on both left and right channels.
	ld			de,PA_CVOL<<8 +CVOL
	call		WritePortB
	
	; Load the address of the sample table.
	ld			ix,SampleTable
	ld			a,$00
.loop:
	cp			c
	jr			nc,.loop_end				; a >= c

	inc			ix
	inc			ix
	inc			ix
	inc			ix

	inc			a
	jr			.loop
.loop_end:

	; Sample's start address LSB

	; Start by generating the correct address for the channel we need to write to.
	ld			a,PA_STARTL					; Load the start address LSB
	add			b							; Then add the channel number, 0 is ch1, 1 is ch2m, etc...
	ld			d,a							; Copy the value of the address we need to write to d.

	; Generate the value.
	ld			e,(ix)
	call			WritePortB

	; Sample's start address MSB
	ld			a,PA_STARTH
	add			b
	ld			d,a

	ld			e,(ix+1)
	call			WritePortB

	; Sample's end address LSB
	ld			a,PA_ENDL
	add			b
	ld			d,a

	ld			e,(ix+2)
	call			WritePortB

	; Sample's end address MSB
	ld			a,PA_ENDH
	add			b
	ld			d,a

	ld			e,(ix+3)
	call			WritePortB

	; Play the sample.
	ld			de,PA_CTRL<<8 +$01
	call			WritePortB

	ret

	;include "src/z80/check_match.asm"
	include "src/z80/tea.asm"
	include "src/z80/admin_mode.asm"
	include "src/z80/check_match.asm"

; Sample table for the audio we play. This marks the beggining and end
; of the audio samples, so we know when we stop sending bytes.
SampleTable:
	dw			$0000,$000d			; Coin sound