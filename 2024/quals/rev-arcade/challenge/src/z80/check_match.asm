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

CheckMatch:
    push            hl
    push            de

    ld              hl,ENCRYPTED_BUFFER
    ld              de,EncryptedFlag

    ld              b,32                        ; Loop 32 times.
.loop:
    ld              a,(de)                      ; Load the contents of DE into the accumulator.
    cp              (hl)                        ; Check if they are the same.
    jr              NZ,.playNoMatch             ; If they are different, then jump out and play a wrong sound.

    inc             hl
    inc             de

    djnz            .loop

.playMatch:
    call            PlayCorrect
    jp              .done

.playNoMatch:
    call            PlayWrong

.done:
    pop             de
    pop             hl
    ret