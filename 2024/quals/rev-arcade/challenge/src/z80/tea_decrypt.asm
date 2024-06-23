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

Decrypt:
    push                af
    push                hl
    push                de
    push                ix
    push                iy

    ; The decryption!!
    ld                  hl,EncryptedFlag             ; HL will be out input pointer.
    ld                  de,DECRYPTED_BUFFER         ; DE will be out output pointer.
    ; Copy all the contents of the encrypted buffer to the decrypted buffer.
    ld                  b,32
.copy_buffer:
    ld                  a,(hl)
    ld                  (de),a
    inc                 hl
    inc                 de
    djnz                .copy_buffer

    ld                  hl,DECRYPTED_BUFFER         ; DE will be out output pointer.
    ld                  b,4                         ; Loop over all the long words, which is 2 at a time.
.loop:
    push                bc
    ; Encrypt with these parameters:
    
    ; Init V0 with the contents of the current pointer.
    ld                  ix,V0_RAM
    call                InitV
    
    ; Init V1 with the contents of the current pointer.
    ld                  ix,V1_RAM
    inc                 hl
    inc                 hl
    inc                 hl
    inc                 hl
    call                InitV
    dec                 hl
    dec                 hl
    dec                 hl
    dec                 hl
    
    ; Initialize SUM, that's shifting 5 bits to the left on DELTA.
    call                InitSum
    ; Decrypt V0 and V1.
    call                DecryptStep

    ; Load the values to the decrypted buffer from V0.
    ld                  ix,V0_RAM
    ld                  b,4
.loadV0:
    ld                  a,(ix)
    ld                  (hl),a
    
    inc                 hl
    inc                 ix
    
    djnz                .loadV0

    ; Load the values to the decrypted buffer from V1.
    ld                  ix,V1_RAM
    ld                  b,4
.loadV1:
    ld                  a,(ix)
    ld                  (hl),a
    
    inc                 hl
    inc                 ix
    
    djnz                .loadV1

    pop                 bc
    djnz                .loop

    pop                 iy
    pop                 ix
    pop                 de
    pop                 hl
    pop                 af
    ret

DELTA: 
    db                  $de,$ad,$be,$ef

; Initialize V RAM values.
; ix: V_RAM location
InitV:
    push                bc
    push                hl
    push                af

    ld                  b,4
.loop:
    ld                  a,(hl)
    ld                  (ix),a
    
    inc                 hl
    inc                 ix
    
    djnz                .loop
    
    pop                 af
    pop                 hl
    pop                 bc
    ret

; void decrypt (uint32_t v[2], const uint32_t k[4]) {
;    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
;    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
;    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
;    for (i=0; i<32; i++) {                         /* basic cycle start */
;        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
;        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
;        sum -= delta;
;    }                                              /* end cycle */
;    v[0]=v0; v[1]=v1;
; }
; ----------------------------------------
; Decrypt with these parameters:
; v0 = uint32[hl, hl+3]
; v1 = uint32[hl+4, hl'+7]
DecryptStep:
    push                bc
    push                hl
    push                af
    push                ix
    push                iy

    ld                  b,32                        ; We're going to loop over 32 times.

; K0 = KEY_RAM[0]
; K1 = KEY_RAM[1]
; K2 = KEY_RAM[2]
; K3 = KEY_RAM[3]
;
; v0 = de, de + 3
; v1 = de + 4, de + 7
.loop:
    ; -----------------------------------------------
    ; Calculate the fist step, this will update v1.
    ; -----------------------------------------------
    call                CalculateV1

    ; -----------------------------------------------
    ; Calculate the second step, this will update v0.
    ; -----------------------------------------------
    call                CalculateV0

    ; sum -= delta;
    ld                  ix,SUM_RAM
    ld                  iy,DELTA
    ld                  hl,SUM_RAM
    call                SubstractLongWords

    ; Loop to next round.
    djnz                .loop
    
    ; We're done.
    pop                 iy
    pop                 ix
    pop                 af
    pop                 hl
    pop                 bc
    ret

CalculateV0:
    push                ix
    push                iy
    push                hl

    ; *A_RAM = ((v1<<4) + k0)
    ld                  ix,V1_RAM
    ld                  iy,A_RAM
    call                ShiftLeftLongWord

    ld                  ix,A_RAM
    ld                  iy,KEY0
    ld                  hl,A_RAM
    call                SumLongWords

    ; *C_RAM = ((v1>>5) + k1)
    ld                  ix,V1_RAM
    ld                  iy,C_RAM
    call                ShiftRightLongWord

    ld                  ix,C_RAM
    ld                  iy,KEY1
    ld                  hl,C_RAM
    call                SumLongWords

    ; *B_RAM = (v1 + sum)
    ld                  ix,SUM_RAM
    ld                  iy,V1_RAM
    ld                  hl,B_RAM
    call                SumLongWords

    ; ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)
    ; *A_RAM = *A_RAM ^ *B_RAM ^ *C_RAM
    ld                  ix,A_RAM
    ld                  iy,B_RAM
    call                XorLongWords

    ld                  ix,A_RAM
    ld                  iy,C_RAM
    call                XorLongWords

    ; v0 -= *A_RAM
    ld                  ix,V0_RAM
    ld                  iy,A_RAM
    ld                  hl,V0_RAM
    call                SubstractLongWords

    pop                 hl
    pop                 iy
    pop                 ix
    ret

CalculateV1:
    push                ix
    push                iy
    push                hl

    ; *A_RAM = ((v0<<4) + k2)
    ld                  ix,V0_RAM
    ld                  iy,A_RAM
    call                ShiftLeftLongWord

    ld                  ix,A_RAM
    ld                  iy,KEY2
    ld                  hl,A_RAM
    call                SumLongWords

    ; *C_RAM = ((v0>>5) + k3)
    ld                  ix,V0_RAM
    ld                  iy,C_RAM
    call                ShiftRightLongWord

    ld                  ix,C_RAM
    ld                  iy,KEY3
    ld                  hl,C_RAM
    call                SumLongWords

    ; *B_RAM = (v0 + sum)
    ld                  ix,SUM_RAM
    ld                  iy,V0_RAM
    ld                  hl,B_RAM
    call                SumLongWords

    ; *A_RAM = ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    ld                  ix,A_RAM
    ld                  iy,B_RAM
    call                XorLongWords

    ld                  ix,A_RAM
    ld                  iy,C_RAM
    call                XorLongWords

    ; v1 -= *A_RAM;
    ld                  ix,V1_RAM
    ld                  iy,A_RAM
    ld                  hl,V1_RAM
    call                SubstractLongWords

    pop                 hl
    pop                 iy
    pop                 ix
    ret

XorLongWords:
    push                af
    push                bc

    ld                  b,4
.loop:
    ld                  a,(ix)
    xor                 (iy)
    ld                  (ix),a

    inc                 ix
    inc                 iy

    djnz                .loop

    pop                 bc
    pop                 af
    ret

; Will shift 4 bits left (MSB <- LSB) on a long word, filling with 0s.
; ix: The long word pointer.
; iy: The pointer to store the shifted long word.
ShiftLeftLongWord:
    push                af
    push                bc

    ld                  b,3                                 ; Loop 3 times.
.loop:
    ld                  a,(ix)
    or                  a
    sla                 a
    or                  a
    sla                 a
    or                  a
    sla                 a
    or                  a
    sla                 a
    ld                  (iy),a
    ld                  a,(ix+1)
    and                 $f0                                 ; Mask
    ; Move these bits to lower order.
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    
    add                 a,(iy)
    ld                  (iy),a
    
    inc                 ix
    inc                 iy

    djnz                .loop

    ld                  a,(ix)
    or                  a
    sla                 a
    or                  a
    sla                 a
    or                  a
    sla                 a
    or                  a
    sla                 a
    ld                  (iy),a

    pop                 bc
    pop                 af
    ret

; Will shift 5 bits right (MSB -> LSB) on a long word, filling with 0s.
; ix: The long word pointer.
; iy: The pointer to store the shifted long word. 352
ShiftRightLongWord:
    push                af
    push                bc

    inc                 ix
    inc                 ix
    inc                 ix

    inc                 iy
    inc                 iy
    inc                 iy

    ld                  b,3                                 ; Loop 3 times.
.loop:
    ld                  a,(ix-1)                            ; Load byte
    and                 $1f                                ; Mask of 0001 1111
    ; Shift it 3 times towards MSB, so now we have xxxx x000
    or                  a                                   ; Clear CF
    sla                 a
    or                  a                                   ; Clear CF
    sla                 a
    or                  a                                   ; Clear CF
    sla                 a

    ld                  (iy),a                            ; Load the contents of a.

    ld                  a,(ix)                            ; Load byte.
    and                 $e0                                 ; Mask of 1110 0000
    ; Move them 5 to the right.
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a

    add                 a,(iy)                            ; Add the contents of the byte with our masked 'a'.
    ld                  (iy),a

    dec                 ix
    dec                 iy
    djnz                .loop

    ; All what is left is to shift the first byte.
    ld                  a,(ix)
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a
    sra                 a
    res                 7,a

    ld                  (iy),a                               ; Load the content of a

    pop                 bc
    pop                 af
    ret

; Will sum two long words pointed by ix and iy.
; Stores the result in hl. 346
SumLongWords:
    push                bc
    push                hl
    push                ix
    push                iy
    push                af

    ; Pointer to the last byte
    inc                 ix
    inc                 ix
    inc                 ix
    inc                 iy
    inc                 iy
    inc                 iy
    inc                 hl
    inc                 hl
    inc                 hl

    ld                  b,4                                 ; The number of bytes in each number
    or                  a                                   ; A dummy logical instruction, used to clear the carry
.loop:
    ld                  a,(ix)
    adc                 a,(iy)                              ; Add with carry (the 9th bit of the previous addition)
    ld                  (hl),a                              ; Storing the current byte of the result

    ; Move pointers down.
    dec                 ix
    dec                 iy
    dec                 hl

    djnz                .loop

    pop                 af
    pop                 iy
    pop                 ix
    pop                 hl
    pop                 bc
    ret

; Will substract two long words pointed by ix and iy.
; Stores the result in hl.
SubstractLongWords:
    push                bc
    push                hl
    push                ix
    push                iy
    push                af

    ; Pointer to the last byte
    inc                 ix
    inc                 ix
    inc                 ix
    inc                 iy
    inc                 iy
    inc                 iy
    inc                 hl
    inc                 hl
    inc                 hl

    ld                  b,4                                 ; The number of bytes in each number
    or                  a                                   ; A dummy logical instruction, used to clear the carry
.loop:
    ld                  a,(ix)
    sbc                 a,(iy)                              ; Substract with carry (the 9th bit of the previous addition)
    ld                  (hl),a                              ; Storing the current byte of the result

    ; Move pointers down.
    dec                 ix
    dec                 iy
    dec                 hl

    djnz                .loop

    pop                 af
    pop                 iy
    pop                 ix
    pop                 hl
    pop                 bc
    ret

; Shifts left 5 bits DELTA.
InitSum:
    push                ix

    ld                  ix,SUM_RAM
    ld                  (ix),$D5
    inc                 ix
    ld                  (ix),$B7
    inc                 ix
    ld                  (ix),$DD
    inc                 ix
    ld                  (ix),$E0

    pop ix
    ret
