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

;definitions for the YM2610 registers

;AY38910
AY_FINEA	equ  0
AY_COARSEA	equ  1
AY_FINEB	equ  2
AY_COARSEB	equ  3
AY_FINEC	equ  4
AY_CAORSEC	equ  5
AY_NOISE	equ  6
AY_MIXER	equ  7
AY_VOLA	equ  8
AY_VOLB	equ  9
AY_VOLC	equ  10
AY_ENVFINE	equ  11
AY_ENVCOARSE	equ  12
AY_ENVSHAPE	equ  13
;ADPCM-A
PA_CTRL	equ  $00
PA_MVOL	equ  $01
PA_CVOL	equ  $08
PA_STARTL	equ  $10
PA_STARTH	equ  $18
PA_ENDL	equ  $20
PA_ENDH	equ  $28
;ADPCM-B
PB_CTRL	equ  $10
PB_LRSEL	equ  $11
PB_STARTL	equ  $12
PB_STARTH	equ  $13
PB_ENDL	equ  $14
PB_ENDH	equ  $15
PB_FREQL	equ  $19
PB_FREQH	equ  $1A
PB_VOL		equ  $1B
PB_FLAG	equ  $1C
;FM
FM_LFO		equ  $22
FM_TIMERMODE	equ  $27
FM_KON		equ  $28
FM_DETMUL	equ  $30
FM_TL		equ  $40
FM_KSAR	equ  $50
FM_AMDR	equ  $60
FM_SR		equ  $70
FM_SLRR	equ  $80
FM_SSG		equ  $90
FM_FNUM	equ  $A0
FM_FBALG	equ  $B0
FM_LRLFO	equ  $B4

;FM address register writes
;sscc
;c channel
;s slot
;datasheet implies than 11 for channel is not valid, same for YM2612.  remaining channels are accessed in other address port

;FM KON
;ssss0Ccc
;c channel, 11 is illegal
;C channel set select
;cc channel select
;s slot
;1 to s to key on, 0 to key off

;MAME mapping
;3808      cch[0] = &F2610->CH[1];
;3809      cch[1] = &F2610->CH[2];
;3810      cch[2] = &F2610->CH[4];
;3811      cch[3] = &F2610->CH[5];

;1828  /* write a OPN register (0x30-0xff) */
;1829  static void OPNWriteReg(FM_OPN *OPN, int r, int v)
;1830  {
;1831      FM_CH *CH;
;1832      FM_SLOT *SLOT;
;1833  
;1834      UINT8 c = OPN_CHAN(r);
;1835  
;1836      if (c == 3) return; /* 0xX3,0xX7,0xXB,0xXF */
;1837  
;1838      if (r >= 0x100) c+=3;
;1839  
;1840      CH = OPN->P_CH;
;1841      CH = &CH[c];
;1842  
;1843      SLOT = &(CH->SLOT[OPN_SLOT(r)]);

