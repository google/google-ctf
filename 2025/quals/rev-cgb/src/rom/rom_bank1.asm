INCLUDE "../third_party/rev-cgb/hardware.inc"
INCLUDE "src/rom/locations.inc"
INCLUDE "src/rom/macros.inc"

; This is the ROM 1 section, an extra bit of ROM space we have to code all our game stuff.
; We could have more ROM space, but then we need to bank it and it starts to be messy to code.
SECTION "ROM 1", ROMX, BANK[1]

; These are the VRAM0 tiles that Background and OAM will use.
Tiles:
    EXPORT Tiles
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00   ; Background
    db $00, $ff, $00, $ff, $00, $ff, $00, $ff, $00, $ff, $00, $ff, $00, $ff, $00, $ff   ; Colored Background
    db $28, $00, $28, $00, $28, $00, $28, $00, $28, $00, $28, $00, $28, $00, $28, $00   ; Vertical
    db $00, $00, $ff, $00, $00, $00, $ff, $00, $00, $00, $00, $00, $00, $00, $00, $00   ; Horizontal
    
    db $00, $00, $00, $00, $00, $00, $00, $00, $ff, $00, $00, $00, $ff, $00, $00, $00   ; Horizontal 2
    db $00, $00, $07, $00, $08, $00, $13, $00, $24, $00, $28, $00, $28, $00, $28, $00   ; Upper left corner
    db $00, $00, $e0, $00, $10, $00, $c8, $00, $28, $00, $28, $00, $28, $00, $28, $00   ; Upper right corner
    db $28, $00, $28, $00, $28, $00, $28, $00, $c8, $00, $10, $00, $e0, $00, $00, $00   ; Lower right corner
    
    db $28, $00, $28, $00, $28, $00, $24, $00, $13, $00, $08, $00, $07, $00, $00, $00   ; Lower left corner
    db $10, $10, $38, $38, $6c, $6c, $c6, $c6, $fe, $fe, $c6, $c6, $c6, $c6, $c6, $c6   ; A 9
    db $7c, $7c, $22, $22, $22, $22, $3c, $3c, $22, $22, $22, $22, $22, $22, $7c, $7c   ; B
    db $3c, $3c, $66, $66, $c2, $c2, $c0, $c0, $c0, $c0, $c2, $c2, $66, $66, $3c, $3c   ; C
    
    db $f8, $f8, $6c, $6c, $66, $66, $66, $66, $66, $66, $66, $66, $6c, $6c, $f8, $f8   ; D 12
    db $fe, $fe, $66, $66, $62, $62, $78, $78, $78, $78, $62, $62, $66, $66, $fe, $fe   ; E
    db $fe, $fe, $66, $66, $62, $62, $68, $68, $78, $78, $68, $68, $60, $60, $f0, $f0   ; F
    db $3c, $3c, $42, $42, $40, $40, $40, $40, $46, $46, $42, $42, $42, $42, $3c, $3c   ; G
    
    db $42, $42, $42, $42, $42, $42, $7e, $7e, $42, $42, $42, $42, $42, $42, $42, $42   ; H 16
    db $7c, $7c, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $7c, $7c   ; I
    db $04, $04, $04, $04, $04, $04, $04, $04, $04, $04, $04, $04, $44, $44, $38, $38   ; J
    db $44, $44, $44, $44, $48, $48, $70, $70, $48, $48, $44, $44, $44, $44, $44, $44   ; K
    
    db $40, $40, $40, $40, $40, $40, $40, $40, $40, $40, $40, $40, $40, $40, $7c, $7c   ; L 20
    db $44, $44, $6c, $6c, $7c, $7c, $54, $54, $44, $44, $44, $44, $44, $44, $44, $44   ; M
    db $44, $44, $64, $64, $64, $64, $54, $54, $54, $54, $4c, $4c, $4c, $4c, $44, $44   ; N
    db $38, $38, $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $38, $38   ; O
    
    db $78, $78, $44, $44, $44, $44, $44, $44, $78, $78, $40, $40, $40, $40, $40, $40   ; P 24
    db $38, $38, $44, $44, $44, $44, $44, $44, $44, $44, $54, $54, $48, $48, $34, $34   ; Q
    db $78, $78, $44, $44, $44, $44, $44, $44, $78, $78, $44, $44, $44, $44, $44, $44   ; R
    db $38, $38, $44, $44, $40, $40, $38, $38, $04, $04, $04, $04, $44, $44, $38, $38   ; S
    
    db $7c, $7c, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10   ; T 28
    db $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $38, $38   ; U
    db $44, $44, $44, $44, $44, $44, $44, $44, $44, $44, $28, $28, $38, $38, $10, $10   ; V
    db $44, $44, $44, $44, $44, $44, $44, $44, $54, $54, $54, $54, $28, $28, $28, $28   ; W
    
    db $44, $44, $44, $44, $28, $28, $10, $10, $10, $10, $28, $28, $44, $44, $44, $44   ; X 32
    db $44, $44, $44, $44, $28, $28, $28, $28, $10, $10, $10, $10, $10, $10, $10, $10   ; Y
    db $7c, $7c, $04, $04, $08, $08, $10, $10, $20, $20, $40, $40, $40, $40, $7c, $7c   ; Z
    db $00, $00, $00, $00, $1c, $1c, $24, $24, $24, $24, $24, $24, $24, $24, $1a, $1a   ; a 35

    db $20, $20, $20, $20, $2c, $2c, $32, $32, $22, $22, $22, $22, $32, $32, $2c, $2c   ; b
    db $00, $00, $00, $00, $1c, $1c, $22, $22, $20, $20, $20, $20, $22, $22, $1c, $1c   ; c
    db $02, $02, $02, $02, $1a, $1a, $26, $26, $22, $22, $22, $22, $26, $26, $1a, $1a   ; d
    db $00, $00, $00, $00, $1c, $1c, $22, $22, $3e, $3e, $20, $20, $22, $22, $1c, $1c   ; e

    db $08, $08, $14, $14, $10, $10, $3c, $3c, $10, $10, $10, $10, $10, $10, $10, $10   ; f 40
    db $34, $34, $4c, $4c, $44, $44, $44, $44, $3c, $3c, $04, $04, $44, $44, $38, $38   ; g
    db $40, $40, $40, $40, $58, $58, $64, $64, $44, $44, $44, $44, $44, $44, $44, $44   ; h
    db $10, $10, $00, $00, $70, $70, $10, $10, $10, $10, $10, $10, $10, $10, $7c, $7c   ; i

    db $04, $04, $00, $00, $04, $04, $04, $04, $04, $04, $04, $04, $24, $24, $18, $18   ; j 44
    db $20, $20, $20, $20, $24, $24, $28, $28, $30, $30, $28, $28, $24, $24, $24, $24   ; k
    db $70, $70, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $10, $7c, $7c   ; l
    db $00, $00, $00, $00, $6c, $6c, $54, $54, $54, $54, $54, $54, $54, $54, $54, $54   ; m

    db $00, $00, $00, $00, $58, $58, $64, $64, $44, $44, $44, $44, $44, $44, $44, $44   ; n 48
    db $00, $00, $00, $00, $38, $38, $44, $44, $44, $44, $44, $44, $44, $44, $38, $38   ; o
    db $58, $58, $64, $64, $44, $44, $44, $44, $64, $64, $58, $58, $40, $40, $40, $40   ; p
    db $1a, $1a, $26, $26, $22, $22, $22, $22, $26, $26, $1a, $1a, $02, $02, $02, $02   ; q

    db $00, $00, $00, $00, $2c, $2c, $32, $32, $20, $20, $20, $20, $20, $20, $20, $20   ; r 52
    db $00, $00, $00, $00, $1c, $1c, $22, $22, $10, $10, $0c, $0c, $22, $22, $1c, $1c   ; s
    db $10, $10, $10, $10, $3c, $3c, $10, $10, $10, $10, $10, $10, $10, $10, $0c, $0c   ; t
    db $00, $00, $00, $00, $44, $44, $44, $44, $44, $44, $44, $44, $4c, $4c, $34, $34   ; u

    db $00, $00, $00, $00, $44, $44, $44, $44, $44, $44, $28, $28, $28, $28, $10, $10   ; v
    db $00, $00, $00, $00, $44, $44, $44, $44, $54, $54, $54, $54, $54, $54, $28, $28   ; w
    db $00, $00, $00, $00, $44, $44, $28, $28, $10, $10, $10, $10, $28, $28, $44, $44   ; x
    db $00, $00, $00, $00, $44, $44, $44, $44, $24, $24, $18, $18, $10, $10, $60, $60   ; y

    db $00, $00, $00, $00, $7c, $7c, $08, $08, $10, $10, $20, $20, $40, $40, $7c, $7c   ; z
    db $38, $38, $44, $44, $4c, $4c, $54, $54, $64, $64, $44, $44, $44, $44, $38, $38   ; 0 61
    db $10, $10, $30, $30, $50, $50, $10, $10, $10, $10, $10, $10, $10, $10, $7c, $7c   ; 1
    db $38, $38, $44, $44, $04, $04, $08, $08, $10, $10, $20, $20, $40, $40, $7c, $7c   ; 2

    db $38, $38, $44, $44, $04, $04, $18, $18, $04, $04, $04, $04, $44, $44, $38, $38   ; 3 64
    db $08, $08, $18, $18, $28, $28, $48, $48, $7c, $7c, $08, $08, $08, $08, $08, $08   ; 4
    db $7c, $7c, $40, $40, $40, $40, $78, $78, $04, $04, $04, $04, $44, $44, $38, $38   ; 5
    db $38, $38, $44, $44, $40, $40, $78, $78, $44, $44, $44, $44, $44, $44, $38, $38   ; 6

    db $7c, $7c, $44, $44, $04, $04, $08, $08, $10, $10, $10, $10, $10, $10, $10, $10   ; 7
    db $38, $38, $44, $44, $44, $44, $38, $38, $44, $44, $44, $44, $44, $44, $38, $38   ; 8
    db $38, $38, $44, $44, $44, $44, $44, $44, $3c, $3c, $04, $04, $04, $04, $38, $38   ; 9
    db $18, $18, $24, $24, $54, $54, $6c, $6c, $6c, $6c, $54, $54, $20, $20, $1c, $1c   ; @

    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $3c, $3c   ; _ 72
    db $00, $00, $00, $00, $00, $00, $00, $00, $3c, $3c, $00, $00, $00, $00, $00, $00   ; -
    db $10, $10, $20, $20, $20, $20, $40, $40, $20, $20, $20, $20, $20, $20, $10, $10   ; {
    db $10, $10, $08, $08, $08, $08, $04, $04, $08, $08, $08, $08, $08, $08, $10, $10   ; }  

    db $38, $38, $44, $44, $04, $04, $08, $08, $10, $10, $10, $10, $00, $00, $10, $10   ; ?

; 77
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00   ; Top left square
    db $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff   ; Full square

; Splash screen - 79
    db $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$04,$03,$10,$0f
    db $00,$00,$00,$00,$00,$00,$08,$10,$54,$28,$26,$d8,$81,$7f,$23,$dd,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00
    db $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$51,$a0,$09,$f0,$00,$00,$00,$00,$00,$00,$00,$00,$58,$a0,$05,$fd,$05,$f8,$03,$fc
    db $00,$00,$00,$00,$00,$00,$2c,$54,$94,$48,$02,$fc,$02,$fc,$02,$fc,$00,$00,$00,$00,$00,$00,$21,$1e,$44,$3b,$40,$3f,$40,$3f,$43,$3c
    db $00,$00,$01,$00,$02,$03,$e3,$02,$13,$e2,$09,$f0,$04,$f8,$05,$f8,$b8,$50,$04,$fc,$04,$f8,$04,$f8,$04,$f8,$5c,$a4,$f3,$10,$12,$e1
    db $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$80,$40,$10,$e0,$08,$f0,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$80,$40
    db $45,$3a,$80,$7f,$80,$7f,$c0,$bf,$66,$19,$3d,$2c,$01,$01,$00,$00,$02,$fc,$0f,$f2,$05,$f8,$05,$f8,$03,$fd,$01,$ff,$81,$7e,$80,$7f
    db $49,$b0,$05,$fc,$05,$f8,$05,$f9,$04,$f8,$82,$7e,$82,$7c,$83,$7c,$05,$7c,$05,$f8,$05,$f8,$03,$fe,$83,$7c,$83,$7c,$83,$fc,$03,$fc
    db $00,$ff,$00,$ff,$00,$ff,$00,$ff,$00,$ff,$00,$ff,$06,$fd,$06,$fb,$01,$ff,$01,$fe,$01,$fe,$00,$ff,$20,$df,$20,$df,$60,$9f,$60,$ff
    db $43,$3d,$c2,$bc,$c0,$3f,$80,$ff,$80,$7f,$80,$7f,$80,$7f,$43,$fd,$86,$79,$86,$79,$02,$fc,$06,$fd,$0c,$f3,$0c,$fb,$74,$93,$84,$83
    db $0c,$ff,$0c,$f7,$08,$ff,$1c,$e3,$18,$e7,$18,$e7,$18,$e7,$10,$ef,$09,$f0,$06,$f9,$06,$f9,$06,$f9,$00,$ff,$00,$ff,$00,$ff,$00,$ff
    db $10,$e0,$08,$f0,$0a,$f9,$0c,$f2,$18,$e7,$10,$ef,$20,$df,$20,$df,$00,$00,$7a,$84,$01,$be,$00,$ff,$00,$ff,$00,$ff,$28,$d7,$7c,$bb
    db $00,$00,$00,$00,$80,$00,$40,$80,$40,$80,$40,$80,$40,$80,$c0,$40,$00,$00,$00,$00,$02,$05,$08,$07,$10,$0f,$00,$1f,$10,$0f,$10,$0f
    db $c0,$bf,$40,$3f,$60,$5f,$a0,$1f,$40,$bf,$00,$ff,$00,$ff,$00,$ff,$80,$7f,$40,$bf,$40,$bf,$60,$9f,$38,$e7,$4f,$88,$c0,$40,$80,$00
    db $03,$fc,$03,$fc,$07,$f9,$0c,$f0,$38,$c8,$f0,$30,$00,$00,$00,$00,$05,$fd,$04,$fc,$5c,$a4,$f8,$a8,$00,$00,$00,$00,$00,$00,$07,$18
    db $b0,$af,$19,$06,$1b,$0c,$00,$00,$00,$00,$00,$00,$00,$00,$80,$01,$c2,$3c,$42,$bc,$fe,$82,$3c,$28,$00,$00,$2d,$12,$c0,$37,$00,$bf
    db $0c,$03,$0c,$0b,$04,$03,$06,$07,$00,$01,$0b,$04,$d0,$0f,$60,$9f,$20,$df,$30,$cf,$30,$cf,$79,$a6,$8f,$05,$00,$00,$80,$00,$9c,$02
    db $40,$bf,$60,$9f,$e0,$1f,$a0,$1f,$30,$2f,$1a,$05,$09,$0e,$02,$02,$20,$df,$60,$9f,$60,$9f,$60,$9f,$60,$9f,$f0,$6f,$98,$17,$0c,$0b
    db $af,$10,$c1,$3e,$c0,$3f,$c0,$7f,$20,$df,$00,$ff,$01,$fe,$05,$fb,$00,$00,$80,$00,$80,$00,$80,$00,$80,$00,$80,$00,$80,$80,$00,$00
    db $18,$07,$0e,$09,$03,$03,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$03,$fc,$2b,$d4,$bf,$44,$04,$02,$04,$01,$04,$03,$04,$03,$06,$05
    db $8f,$90,$40,$bf,$00,$ff,$00,$ff,$00,$ff,$02,$fd,$0f,$f6,$09,$f0,$80,$40,$20,$c0,$10,$e1,$0a,$f1,$04,$fb,$06,$f9,$06,$f8,$06,$f9
    db $20,$5f,$80,$5f,$00,$bf,$00,$ff,$00,$ff,$07,$fc,$09,$f0,$09,$f0,$60,$83,$14,$e3,$08,$f7,$04,$fe,$00,$ff,$04,$fb,$04,$fb,$04,$fb
    db $00,$7f,$00,$ff,$07,$f8,$0f,$ff,$10,$e0,$10,$f0,$10,$e0,$06,$f9,$60,$9f,$60,$9f,$60,$8f,$20,$1f,$40,$7f,$40,$3f,$40,$3f,$c0,$3f
    db $81,$3e,$40,$bf,$81,$3e,$00,$ff,$03,$fd,$04,$fc,$08,$f0,$0c,$f4,$1f,$00,$a0,$95,$80,$ff,$80,$7f,$80,$7f,$80,$7f,$81,$fe,$40,$3f
    db $87,$44,$31,$c1,$08,$f0,$08,$f0,$08,$f0,$08,$f0,$90,$e0,$80,$00,$5e,$a2,$f8,$a8,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00
    db $02,$01,$03,$02,$00,$01,$01,$01,$00,$00,$00,$00,$00,$00,$00,$00,$06,$f9,$00,$fd,$00,$ff,$80,$7f,$80,$7f,$c0,$bf,$40,$3f,$60,$5f
    db $06,$fd,$02,$f9,$0f,$f0,$02,$fd,$00,$ff,$00,$ff,$c5,$3a,$f2,$2d,$04,$fb,$00,$ff,$00,$ff,$80,$7f,$c0,$3f,$fd,$22,$5f,$da,$c0,$00
    db $04,$fb,$06,$f9,$0f,$f2,$19,$e1,$b0,$40,$60,$80,$80,$80,$00,$00,$00,$ff,$00,$ff,$00,$ff,$c1,$3e,$60,$7f,$0e,$0e,$00,$00,$00,$00
    db $40,$bf,$21,$de,$63,$9c,$42,$bc,$ea,$96,$1c,$1c,$00,$00,$00,$00,$04,$f8,$03,$fc,$82,$7d,$83,$7c,$d5,$aa,$7a,$05,$3f,$3c,$03,$02
    db $40,$7f,$30,$af,$70,$9f,$10,$ef,$00,$ff,$45,$ba,$10,$ef,$ca,$35,$80,$00,$40,$80,$40,$80,$20,$e0,$60,$a0,$00,$c0,$c0,$00,$80,$00
    db $20,$1f,$35,$2a,$10,$0f,$1e,$11,$07,$03,$00,$00,$00,$00,$00,$00,$5d,$92,$46,$86,$c0,$40,$80,$80,$00,$00,$00,$00,$00,$00,$00,$00
    db $80,$80,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$03,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$1c,$14,$ab,$54,$fa,$05,$75,$0a
    db $00,$00,$00,$00,$00,$00,$c0,$00,$c0,$20,$f0,$00,$fe,$02,$5f,$a1,$f3,$8d,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00
    db $01,$00,$03,$00,$06,$01,$0f,$00,$0f,$00,$0f,$00,$0f,$00,$0f,$00,$4a,$b5,$35,$ca,$df,$20,$ff,$00,$ee,$11,$d4,$2a,$c0,$15,$00,$e2
    db $b5,$4a,$76,$89,$ff,$00,$bf,$40,$b0,$4f,$02,$ad,$00,$55,$00,$b1,$c0,$00,$e0,$00,$70,$80,$f8,$00,$f8,$00,$fc,$00,$f8,$08,$38,$c0
    db $0b,$00,$03,$00,$07,$00,$01,$06,$03,$04,$00,$07,$00,$03,$00,$00,$04,$e5,$06,$c4,$04,$c5,$00,$e2,$80,$7a,$00,$f5,$00,$d5,$01,$74
    db $08,$49,$18,$b8,$08,$58,$00,$a1,$00,$af,$00,$55,$c0,$ab,$c0,$2b,$38,$c8,$30,$c0,$38,$c0,$20,$d8,$30,$c8,$30,$c8,$00,$f0,$40,$80
    db $00,$00,$00,$00,$00,$00,$01,$00,$02,$03,$0a,$14,$40,$37,$91,$c5,$41,$7c,$10,$0f,$3c,$07,$7f,$86,$7f,$8e,$3f,$ce,$7f,$8c,$3f,$ec
    db $40,$97,$00,$bf,$0f,$f4,$bf,$4c,$ff,$0c,$ff,$0c,$ff,$0e,$ff,$07,$80,$00,$00,$00,$c0,$00,$d8,$20,$c8,$30,$8a,$66,$80,$75,$90,$7e
    db $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$a0,$60,$01,$01,$01,$01,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00
    db $c3,$bd,$f7,$c9,$8a,$84,$00,$00,$00,$00,$01,$01,$01,$01,$00,$00,$9f,$dc,$ef,$ec,$67,$69,$f3,$f7,$f5,$ff,$ff,$ff,$d7,$df,$ef,$ff
    db $ff,$07,$fe,$06,$fc,$f5,$19,$1b,$57,$ff,$fd,$ff,$bf,$7f,$1e,$bf,$34,$7b,$fb,$f4,$ca,$c4,$e0,$e0,$e0,$e0,$e0,$e0,$f0,$f0,$a0,$e0
    db $f0,$30,$60,$e0,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$01,$01,$01,$03,$03,$03,$03,$03,$02,$02,$02,$04,$04,$00,$04
    db $df,$ff,$ff,$ff,$5f,$ff,$fd,$fd,$dc,$6d,$3c,$27,$19,$05,$09,$3f,$1f,$bf,$1f,$bf,$1f,$ff,$47,$e7,$07,$57,$c7,$3f,$f7,$e7,$e7,$eb
    db $50,$70,$b0,$f0,$50,$d0,$f0,$f0,$f0,$f0,$f0,$f0,$f0,$f0,$e0,$f0,$03,$02,$05,$03,$06,$07,$01,$01,$01,$01,$00,$00,$00,$00,$00,$00
    db $eb,$b1,$51,$ff,$ab,$f9,$19,$ff,$f9,$ff,$01,$07,$01,$07,$01,$07,$e7,$e9,$f7,$b8,$e6,$aa,$f4,$fb,$e6,$6f,$e7,$eb,$e4,$b8,$e0,$fc
    db $10,$20,$90,$00,$00,$00,$00,$90,$10,$50,$e0,$e0,$00,$00,$00,$00,$01,$07,$01,$07,$01,$01,$01,$01,$01,$01,$01,$01,$01,$01,$01,$01
    db $f4,$fc,$e0,$fc,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$e0,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00

    ; Ground - $AE
    db $00, $ff, $41, $be, $b8, $57, $d7, $39, $ef, $72, $ff, $50, $ff, $e7, $ff, $ff
    db $00, $ff, $03, $fc, $78, $87, $df, $62, $ff, $28, $ff, $52, $ff, $db, $ff, $ff
    db $00, $00, $00, $00, $10, $10, $38, $28, $7e, $46, $66, $5e, $ce, $b2, $fe, $fe   ; Rock

    ; OAM tiles
    db $ff, $ff, $9f, $81, $ff, $81, $bf, $99, $a7, $bd, $a5, $bd, $99, $99, $ff, $ff
    db $ff, $ff, $e1, $81, $f1, $81, $c9, $b9, $8d, $f5, $bd, $a5, $99, $99, $ff, $ff

    ; Devil. - b4
    db $00, $00, $00, $00, $00, $00, $00, $00, $20, $10, $20, $10, $3b, $00, $3f, $00
    db $00, $00, $00, $00, $00, $00, $00, $00, $08, $00, $1c, $04, $1c, $24, $f8, $34
    db $00, $00, $00, $00, $1f, $07, $3e, $1d, $7d, $67, $70, $3f, $74, $3f, $70, $5f
    db $0f, $11, $35, $2f, $c0, $7d, $00, $ea, $01, $d4, $00, $aa, $02, $ec, $02, $fc
    db $0c, $f8, $08, $58, $20, $60, $40, $a0, $00, $00, $00, $00, $00, $00, $00, $00
    db $3f, $00, $7f, $00, $7f, $10, $20, $2f, $20, $7d, $78, $7f, $77, $4c, $71, $7f
    db $f1, $30, $f3, $c9, $ff, $03, $bf, $c2, $7f, $d1, $2c, $d3, $1e, $fb, $38, $df
    db $ff, $5a, $e2, $be, $d0, $fd, $d4, $7f, $aa, $ff, $6a, $9f, $35, $ef, $16, $fd
    db $f2, $ac, $03, $be, $01, $ae, $08, $dc, $00, $f0, $90, $f0, $50, $b0, $d0, $e0
    db $00, $00, $00, $00, $80, $80, $00, $00, $00, $00, $00, $00, $00, $00, $60, $80
    db $3f, $00, $1f, $00, $1e, $11, $0f, $0b, $0f, $1b, $00, $00, $00, $00, $00, $00
    db $79, $df, $d3, $bf, $ff, $4a, $ff, $a8, $ff, $d0, $ff, $c0, $ef, $c0, $ef, $cb
    db $f7, $7e, $e6, $01, $fb, $17, $eb, $06, $f9, $06, $ff, $06, $fe, $40, $fe, $80
    db $83, $01, $9f, $1c, $fc, $30, $fc, $68, $bc, $1c, $3c, $10, $20, $10, $30, $00
    db $e0, $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $00, $00, $00, $00, $00, $00, $00, $00, $1c, $10, $e7, $13, $c7, $42, $1f, $20
    db $03, $00, $07, $01, $1d, $0b, $1f, $04, $7a, $a5, $e0, $a0, $80, $00, $80, $00
    db $ff, $30, $df, $60, $bf, $68, $7f, $10, $ff, $41, $ff, $01, $f3, $02, $f3, $01
    db $ff, $00, $fe, $a0, $fe, $40, $fc, $44, $ff, $a0, $f0, $40, $e8, $90, $fe, $00
    db $cc, $04, $0c, $00, $0c, $00, $0c, $00, $f0, $00, $e0, $00, $00, $00, $00, $00
    db $70, $51, $86, $00, $18, $10, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $00, $00, $00, $00, $00, $00, $03, $07, $03, $07, $00, $00, $00, $00, $00, $00
    db $e3, $00, $e0, $00, $e0, $00, $e0, $00, $e0, $00, $00, $00, $00, $00, $00, $00
    db $fe, $08, $0e, $08, $0e, $18, $08, $08, $00, $08, $00, $00, $00, $00, $00, $00

    ; Player
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01, $00, $01, $00, $01
    db $00, $00, $00, $00, $00, $00, $00, $70, $70, $88, $f8, $04, $00, $ff, $00, $84
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $80, $00, $00
    db $00, $01, $00, $01, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $10, $94, $00, $44, $00, $88, $00, $70, $30, $c0, $78, $81, $7e, $c1, $7c, $e1
    db $00, $0f, $00, $01, $00, $3e, $00, $47, $00, $4e, $00, $52, $00, $42, $00, $3c
    db $00, $ff, $30, $ff, $40, $f9, $00, $fa, $20, $7e, $00, $3a, $00, $02, $00, $01
    db $00, $00, $00, $00, $00, $e0, $00, $90, $00, $50, $00, $10, $00, $10, $00, $e0
.end:
    EXPORT Tiles.end

; The Konami code in input byte format, reversed since the input buffer is FIFO.
KonamiCode:
    EXPORT KonamiCode
    db $01, $02, $10, $20, $10, $20, $80, $80, $40, $40
.end:
    EXPORT KonamiCode.end

; Splash Tilemap defines where the tiles should be displayed. One byte per tile, and the
; tile byte defines which tile to use from the loaded ones above.
SplashTilemap:
    EXPORT SplashTilemap
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $5A, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $5B, $5C, $5D, $5E, $5F, $60, $61, $62, $63, $64, $65, $66
    db $67, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $68, $69, $6A, $6B, $6C, $6D, $6E, $6F, $70, $71, $72, $73
    db $74, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $75, $76, $77, $78, $79, $7A, $7B, $7C, $7D, $7E, $7F, $80
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8A, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $8B, $8C, $8D, $8E, $8F, $4F, $4F, $90, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $91, $92, $93, $94, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $95, $96, $97, $98, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $99, $9A, $9B, $9C, $9D, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $9E, $9F, $A0, $A1, $A2, $A3, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $A4, $A5, $A6, $A7, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $A8, $A9, $AA, $AB, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $AC, $AD, $4F, $4F, $4F, $4F, $4F
    db $4F, $4F, $4F, $4F, $4f, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F, $4F
    ds 40, $4f
    db $1b, $1c, $09, $1a, $1c

.end
    EXPORT SplashTilemap.end

; Game background tilemap has the ground and sky only.
GameBackground:
    EXPORT GameBackground
    ds 512, $4f
    ds 32, $B0, $AF
    ds 32, $4E, $4E
.end:
    EXPORT GameBackground.end

; The player tilemap has only four tiles. This will be used in OAM, which means we need to define 4 bytes per tile.
; Y position, X position, tile index and attributes. 
CharacterOAMTilemap:
    EXPORT CharacterOAMTilemap
    db  PLAYER_FLOOR, $10, $d1, $00         ; 0000
    db  PLAYER_FLOOR, $18, $d2, $00         ; 0001
    db  PLAYER_FLOOR, $20, $d3, $00         ; 0010
    db  PLAYER_FLOOR - 8, $10, $cf, $00     ; 0011
    db  PLAYER_FLOOR - 8, $18, $d0, $00     ; 0100
    db  PLAYER_FLOOR - 16, $10, $cc, $00    ; 0101
    db  PLAYER_FLOOR - 16, $18, $cd, $00    ; 0110
    db  PLAYER_FLOOR - 16, $20, $ce, $00    ; 0111
.end:
    EXPORT CharacterOAMTilemap.end

def DEVIL_START_Y equ $00
def DEVIL_START_X equ $a8

; Devil OAM tilemap. These bytes are OAM bytes that draw the devil.
DevilOAMTilemap:
    EXPORT DevilOAMTilemap
    db  DEVIL_START_Y, DEVIL_START_X+8, $b4, $01
    db  DEVIL_START_Y, DEVIL_START_X+16, $b5, $01
    db  DEVIL_START_Y, DEVIL_START_X+24, $b6, $01
    db  DEVIL_START_Y, DEVIL_START_X+32, $b7, $01
    db  DEVIL_START_Y, DEVIL_START_X+40, $b8, $01
    db  DEVIL_START_Y+8, DEVIL_START_X+8, $b9, $01
    db  DEVIL_START_Y+8, DEVIL_START_X+16, $ba, $01
    db  DEVIL_START_Y+8, DEVIL_START_X+24, $bb, $01
    db  DEVIL_START_Y+8, DEVIL_START_X+32, $bc, $01
    db  DEVIL_START_Y+8, DEVIL_START_X+40, $bd, $01
    db  DEVIL_START_Y+16, DEVIL_START_X+8, $be, $01
    db  DEVIL_START_Y+16, DEVIL_START_X+16, $bf, $01
    db  DEVIL_START_Y+16, DEVIL_START_X+24, $c0, $01
    db  DEVIL_START_Y+16, DEVIL_START_X+32, $c1, $01
    db  DEVIL_START_Y+24, DEVIL_START_X+16, $c2, $01
    db  DEVIL_START_Y+24, DEVIL_START_X, $c3, $01
    db  DEVIL_START_Y+24, DEVIL_START_X+8, $c4, $01
    db  DEVIL_START_Y+24, DEVIL_START_X+16, $c5, $01
    db  DEVIL_START_Y+24, DEVIL_START_X+24, $c6, $01
    db  DEVIL_START_Y+24, DEVIL_START_X+32, $c7, $01
    db  DEVIL_START_Y+32, DEVIL_START_X, $c8, $01
    db  DEVIL_START_Y+32, DEVIL_START_X+8, $c9, $01
    db  DEVIL_START_Y+32, DEVIL_START_X+16, $ca, $01
    db  DEVIL_START_Y+32, DEVIL_START_X+24, $cb, $01
.end:
    EXPORT DevilOAMTilemap.end

; An empty line, to be used for displaying the flag.
MACRO BGEmptyLine
    db  $02
    ds  18, $00
    db  $02
    ds  12, $00
ENDM

; The flag background tilemap.
BackgroundTilemap:
    EXPORT BackgroundTilemap
; Top BG part
    db  $05
    ds  18, $03
    db  $06
    ds  12, $00

; String constant 'FLAG'
    db  $02
    ds  7, $00
    db  14          ; F
    db  20          ; L
    db  9           ; A
    db  15          ; G
    ds  7, $00
    db  $02
    ds  12, $00

    BGEmptyLine

; FLAG content:
    db  $02
    ds  40, 0       ; Start with all 0s.
    ds  10, $00
    db  $02
    ds  12, $00

; Bottom BG part
    db  $08
    ds  18, $04
    db  $07
    ds  12,$00
.end:
    EXPORT BackgroundTilemap.end

EncryptedFlag:
    EXPORT EncryptedFlag
    ; Correct flag is the following:
    ; db  11, 28, 14, $4A, 43, 72, 16, 71, 38, 72, 40, 55, 22, 72, 20, 64, 35, 26, 48, 43, 22, 15, 72, 37, 15, 10, 72, 42, 61, 57, 72, 71, 10, 61, 55, 68, 72, 55, 76, $4B
    ; Encrypted flag is the following:
    db  $1c, $17, $c7, $11, $c0, $c6, $c5, $85, $a3, $57, $9d, $f1, $b2, $ae, $01, $51, $e0, $f5, $18, $b1, $af, $7f, $13, $32, $39, $eb, $e6, $26, $96, $26, $8b, $aa, $1f, $23, $00, $37, $86, $7a, $8d, $bc

; ==== Functions ====

; This function XORs an array of 'c' bytes from [de] into [hl], one by one. The result is copied into [hl]
; with length "c".
XORBytes:
    EXPORT XORBytes
    PushAll

.loop:
	ld		a, [de]
	xor		a, [hl]
    ld      [hl+], a
	inc		de
    dec     c
	jr		nz,.loop

	PopAll
	ret

; Uses 'c' to select the subkey from [de] ... [de+3] and stores it in 'b'.
; It's simple enough, get the two lower bits from 'c' and index [de] in a circular
; way to get the key we want.
GetSubKey:
    push    af
    push    hl

    ; This way we transfer the contents of 'de' into 'hl'.
    push    de
    pop     hl

    ld      a, 3
    and     a, c
.loop:
    jr      z,.done
    inc     hl
    dec     a
    jr      .loop
.done:
    ld      b, [hl]

    ; We already popped 'de', so no need to pop it here.
    pop     hl
    pop     af
    ret

; Takes two bytes pointed by [hl] and [hl+1] and encrypts them using b. The result is stored in [hl] and [hl+1].
FeistelRound:
    EXPORT FeistelRound
    PushAll

    ; Calculate R1: L0 xor F(R0, K)
    inc         hl
    ld          a, [hl]
    ; Call the "F" function of the Feistel algorithm.
    call        F
    dec         hl
    xor         a, [hl]

    ; Now 'a' holds the value of the new R1.
    inc         hl
    ld          b, [hl]
    ld          [hl], a
    dec         hl
    ld          [hl], b

    PopAll
    ret

; The Feistel function. Takes the byte in 'a' and the subkey in b.
; and encrypts the result to 'a'.
; This function takes the key in 'b' and reads bit by bit. If the bit is '1' it rotates 'a' to the left,
; if the bit is '0' it rotates 'a' to the right.
F:
    push    bc

    ld      c, 8
.firstLoop:
    bit     0, b
    jr      z,.rotateRight
    rlca
    jr      .continue
.rotateRight:
    rrca
.continue:
    srl     b
    dec     c
    jr      nz,.firstLoop

    pop     bc
    ret

; Generates the 'c' key, it stores the key of length 4 in [de].
; The palette information in VRAM is 40 bytes long, so we need to take the first palette and the second
; palette and operate them together to get the key.
EncryptBytes:
    EXPORT EncryptBytes
    PushAll

    ; Position 'hl' to match the byte we want to read. We want [hl] and [hl+1].
    ld      hl, FLAG_BG_ADDR
    ld      b, 0
    add     hl, bc

    ; Switch to VRAM bank 1.
    ld      a, 1
    ld      [rVBK], a

    ; Read the palette, it's 8 bytes. We'll pick the 4 bytes in the middle and XOR it with the next byte palette.
    ; This value in VRAM1 indicates the palette number (0 to 7), each palette holds 4 colors, and each color is 2 bytes.
    call    WaitForBlank
    ld      a, [hl]

    ; There are 8 palettes, so 'a' holds the pallete number.
    ; We need to get the address of the palette in memory, each palette needs 8 bytes to store all the 4 color information. 
    ; Multiply by 8 to get the palette address we want. That is, the first byte of the palette.
    call    Multiply8
    ; Skip the first two bytes. These are the first 2 colors of the palette. We wnat the 4 colors in the middle.
    add     a, 2

    ld      [rBGPI], a

    ; Now the colors are retrievable. Copy the 4 bytes to [de].
    ; These are the 4 colors in the middle of the given palette.
    ld      c, 4
    push    de
    push    hl
    ld      hl, rBGPI
.loop:
    call    WaitForBlank
    ld      a, [rBGPD]
    ld      [de], a
    inc     de

    inc     [hl]        ; inc [rBGPI]    
    
    dec     c
    jr      nz,.loop

    pop     hl
    pop     de

    ; Now we have the palette color bytes in [de] ... [de+3], now we need to operate on them
    ; with the following palette color bytes.
    ; Now retrieve the next 8 colors, get the 4 in the middle and xor them with the ones in [de]
    inc     hl

    call    WaitForBlank
    ld      a, [hl]
    ; Multiply by 8 to get the palette address we want. That is, the first byte of the palette.
    call    Multiply8
    ; Skip the first two bytes, we're interested in the middle bytes.
    add     a, 2

    ; Get the palette address, set the autoincrement.
    ld      [rBGPI], a
    ld      hl, rBGPI

    ld      c, 4
.xorloop:
    call    WaitForBlank
    ld      a, [rBGPD]
    ld      b, a
    ld      a, [de]
    xor     a, b
    ld      [de], a
    inc     de
    inc     [hl]        ; inc [rBGPI]
    dec     c
    jr      nz,.xorloop

    ; Switch back to VRAM 0
    xor     a
    ld      [rVBK], a
    
    PopAll

    push    af
    push    bc

    ; Do 16 rounds of the Feistel encryption.
    ; We start from 0 because 'c' will define which subkey we need to use.
	ld		c, 0
.encryptLoop:
    ; Get the subkey we need to use in order to encrypt the byte (from [de] ... [de+3]). This will be defined by 'c'
    ; and be 1 byte long. The subkey is stored in 'b'.
    call    GetSubKey

    ; Run one Feistel round, that is xor plus 'F' function.
    call	FeistelRound

    ; Check if 'c' reached 16.
    inc     c
    ld      a, c
    cp      a, 16
    jr      nz,.encryptLoop

    pop     bc
    pop     af
    ret

; Multiplies 'a' by 8.
Multiply8:
    sla     a
    sla     a
    sla     a
    ret
