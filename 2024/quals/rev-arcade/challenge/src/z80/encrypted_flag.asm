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

    org $cafe
EncryptedFlag:
    ; CTF{h@cK1ng_r3tr0_gAm32_F0r_fuN}
    ; CTF{h@cK1ng_r3tr0_gAm32_F0r_fuN}
    ; How many combinations?
    ; 8 + 7+6+5+4 + 2+1+1 + 6+5+4 + 
    ; The combination the user needs to put is the reverse of the following:
    ; a  
    ; C     d               80              +
    ; T     c               40              +
    ; F     b               20              +
    ; {     a               10              +
    ; h     a+b+d           b0              +
    ; @     u+l             05              +
    ; c     w+a             12              +
    ; K     a+b+u+r         39              +
    ; 1     w               02              +
    ; n     b+d             a0              +
    ; g     w+l+b+c         66              +
    ; _     r               08              +
    ; r     a+b+c+w+l       76              +
    ; 3     a+d+r           98              +
    ; t     a+b+c+d         f0              +
    ; r     a+b+c+w+l       76              +
    ; 0     d+b+l           a4              +
    ; _     r               08              +
    ; g     w+l+b+c         66              +
    ; A     a+u+l           15              +
    ; m     a+b             30              +
    ; 3     a+d+r           98              +
    ; 2     l               04              +
    ; _     r               08              +
    ; F     b               20              +
    ; 0     d+b+l           a4              +
    ; r     a+b+c+w+l       76              +
    ; _     r               08              +
    ; f     a+b+c           70              +
    ; u     u+r+d           89              +
    ; N     u+r             09              +
    ; }     u               01              
    ; PlainText: 80 40 20 10 b0 05 12 39 02 a0 66 08 76 98 f0 76 a4 08 66 15 30 98 04 08 20 a4 76 08 70 89 09 01
    ;            C  T  F  {  h  @  c  K  1  n  g  _  r  3  t  r  0  _  g  A  m  e  2  _  F  0  r  _  f  u  N  }
    ; filld 100040:program,20,$80,$40,$20,$10,$b0,$05,$12,$39,$02,$a0,$66,$08,$76,$98,$f0,$76,$a4,$08,$66,$15,$30,$98,$04,$08,$20,$a4,$76,$08,$70,$89,$09,$01
    ; filld 100020:program,10,$de,$ad,$be,$ef,$c5,$f2,$cc,$cd,$44,$f3,$76,$df,$f8,$46,$1c,$48
    ; 0xdeadbeef, 0xc5f2cccd, 0x44f376df, 0xf8461c48
    db    $dc,$b9,$54,$8e,$94,$a8,$ce,$f2,$9a,$ba,$5c,$31,$a7,$c5,$00,$eb,$a6,$85,$7a,$5b,$c9,$b8,$b4,$61,$1c,$1a,$69,$25,$ef,$ec,$a0,$ef
