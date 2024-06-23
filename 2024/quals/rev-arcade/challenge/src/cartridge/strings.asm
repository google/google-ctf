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

Empty:
	dc.b $ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$00
Z80Error:
	dc.b $1a,$25,$1d,$fe,$05,$12,$12,$0f,$12,$00
PressStart:
	dc.b $10,$12,$05,$13,$13,$ff,$13,$14,$01,$12,$14,$00
; 03 8b fc3a b8a6 388f 
Konami:
	dc.b $10,$20,$08,$04,$08,$04,$02,$02,$01,$01
GameRunning:
	dc.b $07,$01,$0d,$05,$ff,$12,$15,$0e,$0e,$09,$0e,$07,$00
WhatAreYouLookingFor:
	dc.b $17,$08,$01,$14,$ff,$01,$12,$05,$ff,$19,$0f,$15,$ff,$0c,$0f,$0f,$0b,$09,$0e,$07,$ff,$06,$0f,$12,$34,$00
AdminPanel:
	dc.b $01,$04,$0d,$09,$0e,$ff,$10,$01,$0e,$05,$0c,$00
InsertCoin:
	dc.b $09,$0e,$13,$05,$12,$14,$ff,$03,$0f,$09,$0e,$00
Player1Start:
	dc.b $28,$29,$10,$0c,$01,$19,$05,$12,$ff,$1e,$ff,$13,$14,$01,$12,$14,$29,$28,$00
InputTheFlag:
    dc.b $09,$0e,$10,$15,$14,$ff,$14,$08,$05,$ff,$06,$0c,$01,$07,$27,$00
Decrypted:
    dc.b $04,$05,$03,$12,$19,$10,$14,$05,$04,$27,$00
InputTheKey:
	dc.b $09,$0e,$10,$15,$14,$ff,$14,$08,$05,$ff,$0b,$05,$19,$27,$00
PressStartToDecrypt:
	dc.b $10,$12,$05,$13,$13,$ff,$13,$14,$01,$12,$14,$ff,$14,$0f,$ff,$04,$05,$03,$12,$19,$10,$14,$00
PressAToSwitchInputs:
	dc.b $10,$12,$05,$13,$13,$ff,$01,$ff,$14,$0f,$ff,$13,$17,$09,$14,$03,$08,$ff,$09,$0e,$10,$15,$14,$13,$00
Decrypting:
	dc.b $04,$05,$03,$12,$19,$10,$14,$09,$0e,$07,$89,$89,$89,$00
Spaces:
	dc.b $ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,$00
Key:
	dc.b $0b,$05,$19,$27,$00