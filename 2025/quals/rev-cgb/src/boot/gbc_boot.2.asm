; This is the second boot ROM, located at $200.
; We'll use this place to put the key that will be stored in the palettes.
; It also holds a lot of useful functions that the boot ROM needs.

INCLUDE "../third_party/rev-cgb/hardware.inc"
INCLUDE "src/rom/locations.inc"

SECTION "Second Boot", ROM0[$0200]

; Expects 'c' to be loaded with a counter and `hl` to have the start
; position in RAM to delete.
; Clears RAM from [hl] up until [hl+c].
; $200
ClearRAM:
    push    af

    xor     a
.loop:
    ld      [hl+], a
    dec     c
    jr      nz,.loop

    pop     af
    ret

; Waits until a frame passed by. We can check this by checking that the Y line passed 144. 
; $208
WaitForVBlank:
    push    af

    ; Check if we're at the 144 line, which means the PPU entered the VBLANK mode.
.loop:
    ld      a, [rLY]
    cp      a, 144
    jr      nz,.loop

    pop     af
    ret

; $212
; Waits for N VBlanks, defined by 'c'.
WaitNVblank:
    push    af

    ld      a, c
.loop:
    call    WaitForVBlank
    dec     a
    jr      nz,.loop

    pop     af
    ret

; $21c
; Copies 'bc' bytes from [de] to [hl].
CopyBytes:
    push  af

.loop:
    ld    a, [de]
    ld    [hli], a
    inc   de
    dec   bc
    ld    a, b
    or    a, c
    jr    nz,.loop

    pop   af
    ret

; $0227
; The OAM tiles for the logo.
Tiles:
    db $3c, $3c, $40, $40, $80, $80, $80, $80, $9c, $9c, $82, $82, $42, $42, $3c, $3c   ;g
    db $1e, $1e, $20, $20, $40, $40, $40, $40, $40, $40, $40, $40, $20, $20, $1e, $1e   ;c
    ; FIXME: The 't' goes a bit too hard maybe?
    db $7e, $7e, $7e, $7e, $18, $18, $18, $18, $18, $18, $18, $18, $18, $18, $18, $18   ;t
    db $3e, $3e, $20, $20, $20, $20, $38, $38, $20, $20, $20, $20, $20, $20, $20, $20   ;f
TilesEnd:

; $0267
; The logo tilemap in OAM.
; It goes: Y position, X position, tile index, attributes.
gctfOAM:
    db $10, $42, $00, $00
    db $10, $4a, $01, $00
    db $10, $52, $02, $00
    db $10, $5a, $03, $00
gctfOAMEnd:

; The logo slowly moving down.
LogoAnimation:
    ld    c, $40            ; Where in Y should we stop.
.loop:
    push  bc                ; Save the state of 'c' so we can use it for something else.
    ld    c, $06            ; How many VBlank we wait until we move down.
    call  WaitNVblank
    pop   bc                ; Restore 'c'.

    ; Move all the letters down by one.
    ; Down in Y direction means incrementing.
    ld    hl,_OAMRAM
    inc   [hl]
    ld    hl,_OAMRAM + 4
    inc   [hl]
    ld    hl,_OAMRAM + 8
    inc   [hl]
    ld    hl,_OAMRAM + 12
    inc   [hl]

    dec   c
    jr    nz,.loop

; Play a BaDing!
    call  PlayBa
    call  PlayDing

; Wait for some time until the Ding! is not heared anymore.
LongPause:
    ; Use this time to load the key.
    call  LoadKey

    ; Let's wait for $1ff frames, which seems enough to hear the sound.
    ld    bc,$01ff
.loop: 
    call  WaitForVBlank
    dec   bc

    ; In order to know if both 'b' and 'c' are 0, OR them together.
    ld    a, b
    or    a, c
    jr    nz,.loop

; Disable audio, let the ROM take control of it.
    ld      a, AUDENA_OFF
    ld      [rAUDENA],a

    ret

; $2a2
; Play a Ba sound.
; This sets the bytes in CH2 to play the sound at the correct pitch.
PlayBa:
    ld		a, $80
	ld		[rAUD2LEN], a
    ld      a, $f0
    ld      [rAUD2ENV], a
    ld      a, $80
    ld      [rAUD2LOW], a
    ld      a, $87
    ld      [rAUD2HIGH], a          ; At this moment the sound is heard.

    ; Wait some time to let the audio be.
    ld      c, $20
    call    WaitNVblank

    ret

; $2b7
; Play a Ding sound.
; This sets the bytes in CH2 to play the sound at the correct pitch, should be an octave
; higher than the first sound.
PlayDing:
    ld		a, $80
	ld		[rAUD2LEN], a
    ld      a, $f4
    ld      [rAUD2ENV], a
    ld      a, $c0
    ld      [rAUD2LOW], a
    ld      a, $87
    ld      [rAUD2HIGH], a          ; At this moment the sound is heard.

    ret

; These must be 3 bit long, because that's the amount of palettes the Background/Window have.
; These represent which palette bytes we need to lookup in order to generate the real key used in the encryption.
Key:
    db $07, $01, $00, $05, $04, $03, $06, $02, $07, $00, $01, $05, $03, $04, $02, $06, $00, $07, $05, $01, $03, $04, $06, $02, $07, $00, $05, $01, $03, $04, $02, $06, $07, $00, $01, $05, $03, $04, $02, $06

; Loads the palette key order into FLAG_BG_ADDR. This will be later used to retrieve the actual bytes for the key.
LoadKey:
    ld      hl, FLAG_BG_ADDR

    ; Switch to VRAM bank 1.
    ld      a, 1
    ld      [rVBK], a

    ld      de, Key
    ld      c, 40
.loop:
    ld      a, [de]
    call    WaitForVBlank
    ld      [hl+], a
    inc     de
    dec     c
    jr      nz,.loop

    ; Switch to VRAM bank 0.
    xor     a
    ld      [rVBK], a

    ret

; Pad with $00 until we get to the end of the boot ROM.
    ds $8FF - $200
