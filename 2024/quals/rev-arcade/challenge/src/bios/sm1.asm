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

; sm1, default sound driver.

    org $00
Reset:
	ld				sp,$ffff			; Reset the stack pointer to the end of RAM.
	out				($08),a				; Enable NMI.
; Hang in RAM until NMI happens. 
.loop:
	jr	.loop

    ; NMI from YM2610, just ignore.
    org	$38
	retn

    ; Command from m68k.
    org $66
    in				a,($00)

    cp			    $01
	jr			    z,PrepareSwitch

    cp			    $03
	jr			    z,Reset

    retn

PrepareSwitch:
    set			7,a						; Set bit 7 so the m68k knows we are working.
	out			($0C),a					; Send byte to out port.
	jp			Reset                   ; Blindly jump to Reset.

    db    "It's dangerous to go alone! Take this."
    db    $00
    db    "Oh wait, I got nothing here for you. Go and look somewhere else."
