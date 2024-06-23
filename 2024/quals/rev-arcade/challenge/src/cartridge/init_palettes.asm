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

PALETTE1    equ PALETTES+32
PALETTE2    equ PALETTE1+32
PALETTE3    equ PALETTE2+32
PALETTE4    equ PALETTE3+32
PALETTE5    equ PALETTE4+32
PALETTE6    equ PALETTE5+32
PALETTE7    equ PALETTE6+32
PALETTE8    equ PALETTE7+32

InitPalettes:
	move.w	#BLACK,PALETTES		; Transparency, color 0 of palette 0 must always be black anyways
    move.w  #BLUE,BACKDROP      ; Set the back color.

; Fix layer palette.
    move.w	#WHITE,PALETTES+6	; Fix layer text color
    move.w  #BLUE,PALETTES+12   ; Backdrop for text?

    ; Google LOGO palette.
    move.w  #BLACK,PALETTE1     ; Color 0 - Palette 1
    move.w  #BLACK,PALETTE1+2

    ; Fix layer Admin palette.
    move.w  #BLACK,PALETTE2     ; Color 0 - Palette 2
    move.w  #WHITE,PALETTE2+6
    move.w  #MIDGREEN,PALETTE2+12

    ; Google logo Admin palette.
    move.w  #BLACK,PALETTE3     ; Color 0 - Palette 3
    move.w  #RED,PALETTE3+26

    ; Background sprite.
    move.w #$b007,PALETTE4+0
    move.w #$4310,PALETTE4+2
    move.w #$5239,PALETTE4+4
    move.w #$1842,PALETTE4+6
    move.w #$7953,PALETTE4+8
    move.w #$1b75,PALETTE4+10
    move.w #$0bbb,PALETTE4+12
    move.w #$7fff,PALETTE4+14
    move.w #$20f0,PALETTE4+16
    move.w #$20f0,PALETTE4+18
    move.w #$20f0,PALETTE4+20
    move.w #$20f0,PALETTE4+22
    move.w #$20f0,PALETTE4+24
    move.w #$20f0,PALETTE4+26
    move.w #$20f0,PALETTE4+28
    move.w #$20f0,PALETTE4+30

    ; Chest
    move.w #$8000,PALETTE5+0
    move.w #$4310,PALETTE5+2
    move.w #$1842,PALETTE5+4
    move.w #$7953,PALETTE5+6
    move.w #$1b75,PALETTE5+8
    move.w #$5fc0,PALETTE5+10
    move.w #$20f0,PALETTE5+12
    move.w #$20f0,PALETTE5+14
    move.w #$7fff,PALETTE5+16
    move.w #$7fff,PALETTE5+18
    move.w #$7fff,PALETTE5+20
    move.w #$7fff,PALETTE5+22
    move.w #$7fff,PALETTE5+24
    move.w #$7fff,PALETTE5+26
    move.w #$7fff,PALETTE5+28
    move.w #$7fff,PALETTE5+30

    ; Robot
    move.w #$f777,PALETTE6+0
    move.w #$000f,PALETTE6+2
    move.w #$8000,PALETTE6+4
    move.w #$8333,PALETTE6+6
    move.w #$8888,PALETTE6+8
    move.w #$400f,PALETTE6+10
    move.w #$1178,PALETTE6+12
    move.w #$1178,PALETTE6+14
    move.w #$7fff,PALETTE6+16
    move.w #$7fff,PALETTE6+18
    move.w #$7fff,PALETTE6+20
    move.w #$7fff,PALETTE6+22
    move.w #$7fff,PALETTE6+24
    move.w #$7fff,PALETTE6+26
    move.w #$7fff,PALETTE6+28
    move.w #$7fff,PALETTE6+30

    ; Trash msg
    move.w #BLACK,PALETTE7+0
    move.w #WHITE,PALETTE7+2                ; Letters
    move.w #MAGENTA,PALETTE7+4                ; Border
    move.w #WHITE,PALETTE7+6
    move.w #WHITE,PALETTE7+8
    move.w #WHITE,PALETTE7+10
    move.w #WHITE,PALETTE7+12              
    move.w #WHITE,PALETTE7+14
    move.w #WHITE,PALETTE7+16
    move.w #WHITE,PALETTE7+18
    move.w #WHITE,PALETTE7+20
    move.w #WHITE,PALETTE7+22
    move.w #WHITE,PALETTE7+24
    move.w #WHITE,PALETTE7+26
    move.w #WHITE,PALETTE7+28              ; Letters
    move.w #WHITE,PALETTE7+30             ; Shadow

    ; Player start palette
    move.w #BLACK,PALETTE8+0
    move.w #MIDGREEN,PALETTE8+2                ; Letters
    move.w #WHITE,PALETTE8+4                ; Border
    move.w #WHITE,PALETTE8+6
    move.w #WHITE,PALETTE8+8
    move.w #WHITE,PALETTE8+10
    move.w #WHITE,PALETTE8+12              
    move.w #WHITE,PALETTE8+14
    move.w #WHITE,PALETTE8+16
    move.w #WHITE,PALETTE8+18
    move.w #WHITE,PALETTE8+20
    move.w #WHITE,PALETTE8+22
    move.w #WHITE,PALETTE8+24
    move.w #WHITE,PALETTE8+26
    move.w #WHITE,PALETTE8+28              ; Letters
    move.w #WHITE,PALETTE8+30             ; Shadow

    rts                         ; Return from subroutine.