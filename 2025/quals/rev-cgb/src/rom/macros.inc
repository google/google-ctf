
MACRO ShiftLeft4
	sla a
	sla a
	sla a
	sla a
ENDM

MACRO PushAll
	push	af
	push	bc
	push	de
	push	hl
ENDM

MACRO PopAll
	pop		hl
	pop		de
	pop		bc
	pop		af
ENDM

; Load 'hl' with $ff + a.
; This is used so people don't quickly find where the input register is being used.
MACRO DecodeRegisterFF
	ld		b, $01
	dec		b
	dec		b
	ld		h, b
	ld		l, a
ENDM
