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

; Subroutine to compare the encrypted buffer with the encrypted flag constant.
; It should play a "correct" sound if both match, and "wrong" sound if they don't
CheckMatch:
    push            hl
    push            de

    ld              hl,ENCRYPTED_BUFFER		; Load the Encrypted buffer.
    ld              de,EncryptedFlag		; Load the flag encrypted constant.

    ld              b,32                        ; Loop 32 times, the length in bytes for the encrypted content.
.loop:
    ld              a,(de)                      ; Load the contents of DE into the accumulator.
    cp              (hl)                        ; Check if they are the same.
    jr              NZ,.playNoMatch             ; If they are different, then jump out and play a wrong sound.

    ; Move forward 1 byte on each array.
    inc             hl
    inc             de

    djnz            .loop			; Loop if we're not done comparing.

; If we're here then it means both arrays are the same.
.playMatch:
    call            PlayCorrect			; Play a "correct" sound.
    jp              .done			; Jump to done so we skip the subroutine below.

; If we're here then the arrays don't match.
.playNoMatch:
    call            PlayWrong			; Play a "wrong" sound.

; Pop everything we used and return from subroutine.
.done:
    pop             de
    pop             hl
    ret

