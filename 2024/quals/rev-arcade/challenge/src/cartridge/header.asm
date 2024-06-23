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

; Minimal header so our game is recogized by the system ROM and launched.
; This comes from here: https://wiki.neogeodev.org/index.php?title=68k_program_header#Minimal_header_(from_Smkdan's_sources)
	org $0000	; Reset stack pointer.
	dc.l $10F300

	org $0004	; Reset program counter.
	dc.l $C00402

	org $0064	; V-Blank interrupt: Every ~60 times per second, right before a frame is drawn.
	dc.l VBLANK	;IRQ handler

	org $0068
	dc.l TIMER_INT

	org $0100	; User interrupt.
	dc.b "GCTF"

	org $0107
	dc.b $00		; System version cartdrige.

	org $0108
	dc.w $1234	;NGH

	org $0122
	jmp USER	;entry

	org $0128
	jmp PLAYER_START

	org $0134
	jmp COIN_SOUND

	org $0114
	dc.w $0100	;logo flag, don't show it just go straight to the entry point

	org $0182
	dc.l Code	;code pointer
Code:
	dc.l $76004A6D,$0A146600,$003C206D,$0A043E2D
	dc.l $0A0813C0,$00300001,$32100C01,$00FF671A
	dc.l $30280002,$B02D0ACE,$66103028,$0004B02D
	dc.l $0ACF6606,$B22D0AD0,$67085088,$51CFFFD4
	dc.l $36074E75,$206D0A04,$3E2D0A08,$3210E049
	dc.l $0C0100FF,$671A3010,$B02D0ACE,$66123028
	dc.l $0002E048,$B02D0ACF,$6606B22D,$0AD06708
	dc.l $588851CF,$FFD83607
	dc.w $4e75
