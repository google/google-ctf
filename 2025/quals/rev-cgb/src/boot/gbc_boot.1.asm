; Game Boy hardware runs first a boot rom that is stored inside the console,
; and then loads the ROM that was inserted. There were many variations of
; boot ROMs depending on the type of hardware used, in this example I took
; the Game Boy Color which uses a two part boot ROM: The first one goes from
; $0000 - $00FF while the second part goes from $0200-08FF. The part in the
; middle is saved for the inserted ROM header and it would usually take over
; the entire memory (since the boot ROM would erase itself after booting).
;
; https://gbdev.io/pandocs/Power_Up_Sequence.html

; This boot ROM has two jobs: one it prepares all the registers and shows a
; nice "gctf" logo as a welcome message; and the second job is to load the
; actual key into the palettes. The key is located within the middle 4 bytes
; (2 colors) of the 8 palettes for the Background/Window.

INCLUDE "../third_party/rev-cgb/hardware.inc"

; Useful constants and location in memory.
def LOGO_TILES equ $0227
def LOGO_TILES_END equ $0267
def LOGO_OAM equ LOGO_TILES_END
def LOGO_OAM_END equ $0277
def LOGO_ANIMATION equ LOGO_OAM_END

SECTION "First Boot", ROM0[$0]
    ; Disable all interrupts, we're not gonna use them.
    di

; Initialize the stack. HRAM starts at FF80 and stops at FFFE.
; The stack pointer starts at FFFE and goes upwards (like all stacks do).
; This CPU does not have different base stack and top stack pointers, just one pointer for the
; top of the stack. So watch out for stack underflow!
    ld    sp,$FFFE
    jr    BootInit

; These are general use palettes, the middle 4 bytes of each palette are used for key generation.
; Each palette has their first and last colors as black and white, which will be used to display
; the letters for the flag.
Palettes:
    ; Palette 0
    db    $ff, $ff
    db    $03, $1c
    db    $37, $5b
    db    $00, $00

    ; Palette 1
    db    $ff, $ff
    db    $7f, $42
    db    $3d, $0a
    db    $00, $00
    
    ; Palette 2
    db    $ff, $ff
    db    $76, $5b
    db    $61, $1c
    db    $00, $00

    ; Palette 3
    db    $ff, $ff
    db    $2e, $79
    db    $64, $11
    db    $00, $00

    ; Palette 4
    db    $ff, $ff
    db    $40, $33
    db    $58, $35
    db    $00, $00

    ; Palette 5
    db    $ff, $ff
    db    $7a, $7d
    db    $4c, $22
    db    $00, $00
    
    ; Palette 6
    db    $ff, $ff
    db    $0f, $4a
    db    $56, $65
    db    $00, $00

    ; Palette 7
    db    $ff, $ff
    db    $13, $78
    db    $f7, $69
    db    $00, $00

; These two palettes are used by the OAM (tiles that can be individually moved, pixel per pixel).
; There is no hidden information here.
OAMPalettes:
    ; Player.
    db  $ff, $ff
    db  $88, $88
    db  $66, $66
    db  $00, $00

    ; Devil.
    db  $e0, $00
    db  $7f, $42
    db  $3d, $0a
    db  $00, $00

; Start of the boot process.
BootInit:

; HRAM is where the Stack pointer lives, so let's clear it first.
; We can't use 'call' here because the SP uses this RAM.
; This routine goes through the entire HRAM space and clears it up.
; MAME usually clears this for us, but it doesn't hurt to do it
; ourselves.
ClearHRAM:
    xor     a
    ld      hl, _HRAM
    ld      c, $7F
.loop:
    ld      [hl+],a
    dec     c
    jr      nz,.loop

; Set up audio for the BaDing! sound when booting.
EnableAudio:
    ; Turn on the Audio, the rest of the bits are read-only.
    ld      a, AUDENA_ON
    ld      [rAUDENA],a

    ; Audio panning, either to left or right. We just make all channels the same volume
    ; on each side.
	ld		a, $ff
	ld		[rAUDTERM], a

    ; Master volume and external audio. Just make everything max.
    ; https://gbdev.io/pandocs/Audio_Registers.html#ff24--nr50-master-volume--vin-panning
	ld		a, $77
	ld		[rAUDVOL], a

    ; Setup Channel 2.
    ; This works like Channel 1 but does not have a period sweep, this will be useful
    ; as a piano-like instrument.
    ; This is a square wave, we set it up now and then control it's frequency,
    ; thus making notes.
    ; Duty cycle of 50%, perfect square wave.
    ld      a, AUDLEN_DUTY_50
    ld      [rAUD2LEN], a

    ; Channel envelope.
    ld      a, AUDENVF_INIT_VOL
    ld      [rAUD2ENV], a

; WRAM has bank 0 in $C000 - $CFFF
; Let's clear it up.
ClearWRAM0:
    ld      hl,_RAM
    ld      a, $10
    ; Each loop clears ram from $00 to $ff, so it slowly grows until it covers $C000 to $CFFF.
.loop:
    ld      c, $ff
    call    $200        ; ClearRAM
    dec     a
    jr      nz,.loop

; rSVBK, select WRAM bank. In this case bank 1.
; Bank 0 is always available.
    xor   a
    ldh   [rSVBK],a

; WRAM has bank 1 in $D000 - $DFFF
ClearWRAM1:
    ld    hl,_RAMBANK
    ld    a,$10
.loop:
    ld    c,$FF
    call  $200          ; ClearRAM
    dec   a
    jr    nz,.loop

; Set-up the palettes.
; BGP: https://gbdev.io/pandocs/Palettes.html#ff47--bgp-non-cgb-mode-only-bg-palette-data
; This sets the shades of gray, not really used by 'cgb' but we set them up anyway.
; The shading is easy: Two bits per shade and there are 4 shades, bit 0-1 is white and bit 6-7 is black.
    ld    a, BGP_SGB_TRANSFER
    ld    [rBGP],a

; Set-up the color palettes. We do this by setting up an index and writing to the data register rBGPD.
; There are 8 palettes with 4 colors or "shades" and 2 byte per color, so 64 bytes can be addressed.
; https://gbdev.io/pandocs/Palettes.html?highlight=FF47#ff68--bcpsbgpi-cgb-mode-only-background-color-palette-specification--background-palette-index
SetupPalettes:
    ld    a, BGPIF_AUTOINC     ; This means that it'll autoincrement the index for each write to rBGPD.
    ld    [rBGPI], a
    ld    c, BGPIF_INDEX       ; This starts a counter that reaches 0 after 64 passes.
    ld    de, Palettes         ; Load the address of the defined palettes.
.loop:
    ld    a, [de]
    ld    [rBGPD], a
    inc   de
    dec   c
    jr    nz,.loop

; Do the same but for the OAM palettes. These are separate from the Background and Window palettes.
SetupOAMPalettes:
    ld    a, OBPIF_AUTOINC     ; This means that it'll autoincrement the index for each write to rOBPI.
    ld    [rOBPI], a
    ld    c, 16               ; We only have 2 palettes, so 16 bytes.
    ld    de, OAMPalettes     ; Load the address of the defined palettes.
.loop:
    ld    a, [de]
    ld    [rOBPD], a          ; rOBPI auto-increments on every write.
    inc   de
    dec   c
    jr    nz,.loop

; Load the GCTF logo to VRAM.
; This loads the tiles of the GCTF logo into VRAM for us to use.
LoadGCTFLogo:
    ld    hl, _VRAM
    ld    de, LOGO_TILES
    ld    bc, LOGO_TILES_END - LOGO_TILES
	call    $21C                        ; CopyBytes

; Load the logo tilemap to OAM. We can access it directly because the PPU is off.
LoadOAM:
    ld    hl,_OAMRAM
    ld    de,LOGO_OAM
    ld    bc,LOGO_OAM_END - LOGO_OAM
    call    $21C                        ; CopyBytes

; LCD control: https://gbdev.io/pandocs/LCDC.html?highlight=LCDC#lcd-control
; LCD & PPU enabled
; BG & Window priority enabled: https://gbdev.io/pandocs/Tile_Maps.html#bg-to-obj-priority-in-cgb-mode
; Turn OAM on as well since that's the logo that we'll display.
    ld    a, LCDCF_ON | LCDCF_BGON | LCDCF_OBJON
	ld    [rLCDC], a

    call    $208                        ; WaitForVBlank

    ; Animate the logo down.
    call    LOGO_ANIMATION

; Pad with $00 until we get to the end of the boot ROM. That's when we call the
; load function to trigger the boot erase feature.
    ds $FC - @

BootErase:
; Disable Boot ROM. This effectively clears all bytes from $0000 - $0100.
; So this ends up being a NOP slide towards $0100, which is where the game ROM
; starts.
    ld   a,$11
    ldh  [$FF50], a

BootEnd:
  IF BootEnd > $0100
    FAIL "Boot rom is {BootEnd} long, must not be greater than $0100."
  ENDC
; Boot ROM ends at $100 and then hands it over to the cartridge ROM. 
    ds $100 - @
