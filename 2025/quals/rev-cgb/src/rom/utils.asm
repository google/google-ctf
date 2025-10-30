INCLUDE "../third_party/rev-cgb/hardware.inc"

; These functions will be mapped to $0000 after the rom boots, makes things more
; convoluted.

SECTION "Exported Functions", ROM0[0]

WaitForVBlank:
    EXPORT WaitForVBlank
    push    af
.loop:
    ld      a,[rLY]
    cp      a,144
    jr      nz,.loop
    pop     af
    ret

; Copies the bytes from 'de' into 'hl' with size 'bc'.
CopyToRAM:
    EXPORT CopyToRAM
    push    af
.loop:
	ld a, [de]
	ld [hli], a
	inc de
	dec bc
	ld a, b
	or a, c
	jp nz,.loop

    pop af
    ret

; Copies the bytes from 'de' into 'hl' with size 'bc'.
; This works the same as CopyToRAM except it takes care to only
; write data to VRAM if we're in HBLANK or VBLANK.
CopyToVRAM:
    EXPORT CopyToVRAM
    push    af
.loop:
    call WaitForBlank
	ld a, [de]
	ld [hli], a
	inc de
	dec bc
	ld a, b
	or a, c
	jp nz,.loop

    pop af
    ret

; Expects 'bc' to be loaded with a counter and `hl` to have the start
; position in RAM to delete.
ClearRAM:
    EXPORT ClearRAM
    push    af
.loop:
    xor     a
	ld      [hl+],a
	dec     bc
	ld      a, b
	or      a, c
	jp      nz,.loop

    pop     af
    ret

WaitForBlank:
    EXPORT WaitForBlank
    push    hl
    ld      hl, rSTAT
.loop
    bit     1, [hl]       ; Wait until Mode is 0 or 1
    jr      nz, .loop

    pop     hl
    ret
