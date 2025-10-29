; ROM's header: https://gbdev.io/pandocs/The_Cartridge_Header.html
SECTION "Header", ROM0[$100]
    ; Game Boy ROMs usually do this, the actual game starts at $150.
	jp EntryPoint

; Is not mandatory to fill the header (since we have a custom boot ROM), but we do it anyway.
; If people use some kind of disassembler for Game Boy ROMs it'll surely check these places.
SECTION "Logo", ROM0[$104]
    db "GCTF LOGO"

SECTION "Title", ROM0[$134]
    db "GCTF", 0

SECTION "Manufacturer code", ROM0[$13F]
    db "NICO"

SECTION "CGB Flag", ROM0[$143]
    db $80      ; https://gbdev.io/pandocs/The_Cartridge_Header.html#0143--cgb-flag

SECTION "License code", ROM0[$144]
    db $00

SECTION "SGB flag", ROM0[$146]
    db $00

SECTION "Destination Code", ROM0[$14A]
    db $01
