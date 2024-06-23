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

; TEA_Decrypt decrypts two blocks of long words (32 bit).
; The input of two long words can be found at INPUT_ARRAY, so
; (uint32_t)INPUT_ARRAY     -> v[0]
; (uint32_t)INPUT_ARRAY+32  -> v[1]
; TEA_KEY defined by input.

TEA_RAM_DECRYPTED       equ $103000
TEA_RAM_ENCRYPTED_FLAG  equ $103100
KEY_SCHEDULE            equ $9e3779b9

TEA_Decrypt:
    movem.l         d0-d6/a0-a5,-(sp)
    ; Load the key from memory.
    lea            INPUT_ARRAY,a0
    lea            INPUT_ARRAY+4,a1
    lea            INPUT_ARRAY+(2*4),a2
    lea            INPUT_ARRAY+(3*4),a3

    ; Set up a counter.
    clr.l          d6

    ; Load 2 pointers, one for the encrypted flag and one for the decrypted flag.
    lea             TEA_RAM_ENCRYPTED_FLAG,a4
    lea             TEA_RAM_DECRYPTED,a5
.loop:
    ; Copy the values from RAM for TEA.
    move.l          (a4,d6),d0                         ; v0
    addi.l          #4,d6

    move.l          (a4,d6),d1                         ; v1

    ; Actual decryption.
    ; uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    move.l      #$c6ef3720,d2                                      ; sum
    
    ; for (i=0; i<32; i++)                         /* basic cycle start */
    clr.l       d3                                                  ; i = 0
.decryptLoop:
    cmpi.l      #32,d3                                              ; i< 32
    bge         .decrypt_done

    ; (v0 + sum)
    move.l      d0,d4
    add.l       d2,d4

    ; ((v0>>5) + k3)
    move.l      d0,d5
    lsr.l       #5,d5
    add.l       (a3),d5

    ; (v0 + sum) ^ ((v0>>5) + k3)
    eor.l       d5,d4

    ; ((v0<<4) + k2)
    move.l      d0,d5
    lsl.l       #4,d5
    add.l       (a2),d5

    ; ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3)
    eor.l       d5,d4

    ; v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    sub.l       d4,d1

    ; (v1 + sum)
    move.l      d1,d4
    add.l       d2,d4

    ; ((v1>>5) + k1)
    move.l      d1,d5
    lsr.l       #5,d5
    add.l       (a1),d5

    ; (v1 + sum) ^ ((v1>>5) + k1)
    eor.l       d5,d4

    ; ((v1<<4) + k0)
    move.l      d1,d5
    lsl.l       #4,d5
    add.l       (a0),d5

    ; ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)
    eor.l       d5,d4

    ; v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
    sub.l      d4,d0

    ; sum -= delta;
    subi.l      #KEY_SCHEDULE,d2

    addi.l      #1,d3                                               ; i++
    bra         .decryptLoop

.decrypt_done:
    sub.l       #4,d6
    move.l      d0,(a5,d6)
    addi.l      #4,d6
    move.l      d1,(a5,d6)
    addi.l      #4,d6
    
    cmp.l       #32,d6
    blo         .loop

    ; Mark the last byte with $00 so we can print it.
    move.b      $00,TEA_RAM_DECRYPTED+32

    movem.l         (sp)+,d0-d6/a0-a5
    rts                                 ; Return from subroutine.