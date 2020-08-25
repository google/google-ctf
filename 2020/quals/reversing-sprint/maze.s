; Copyright 2020 Google LLC
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
; =================================
; generate primes
mov r0, is_nonprime
mov dptr, r0
mov *dptr, 1 ; 0 is nonprime
add dptr, r0 2
mov *dptr, 1 ; 1 is nonprime

mov r1, 2
prime_loop:
	add r4, r1 r1
	add dptr, is_nonprime r4
	mov r3, *dptr
	jnz r3 prime_loop_next
	; if r1 is prime:
	; mark multiples of r1 as composite
	add r2, r1 r1
	prime_inner:
		; first test if r2 < 256
		mov dptr, scratch_minus_1
		mov *dptr, r2
		mov dptr, scratch
		mov r3, *dptr
		jnz r3, prime_loop_next
		; now write is_nonprime[r2]=1
		add r4, r2 r2
		add dptr, is_nonprime r4
		mov *dptr, 1
		add r2, r2 r1
		jmp prime_inner
	
	prime_loop_next:
	add r1, r1 1
	jnz r1, prime_loop

; ======================================
; calculate pass length
mov r0, pass
mov r1, 0 ; negative of pass length
keylen_lp:
	mov dptr, r0
	mov r2, *dptr
	jnz r2 keylen_lp_continue
	jmp after_keylen_lp
	keylen_lp_continue:
	add r1, r1 -1
	add r0, r0 1
	jmp keylen_lp	
after_keylen_lp:

add r4, r1 passlength
jnz r4 wrong_length
jmp maze_thing
wrong_length:
mov r7, 5 ; fail 5 - wrong pass length
jmp fail

; =============================
; do the maze thing

maze_thing:
mov r0, 0 ; r0 - current char index
mov r1, 0 ; r1 - current achieved position index
mov dptr, start
mov r2, *dptr ; r2 - current position
mov r3, 1 ; r3 - flag (1 - still ok, 0 - not ok)
mov r7, 0

main_loop:
	add dptr, pass r0
	mov r4, *dptr ; r4 - current char move
	jnz r4, main_loop1
	jmp after_main_loop ; if NUL, end
	main_loop1:
	add r0, r0 1

	; test the direction
		add r5, r4 -117
		jnz r5 main_not_u
		main_u:
			mov r4, -16 ; up
			jmp main_loop_continue
		main_not_u:
		add r5, r4 -114
		jnz r5 main_not_r
		main_r:
			mov r4, 1 ; right
			jmp main_loop_continue
		main_not_r:
		add r5, r4 -100
		jnz r5 main_not_d
		main_d:
			mov r4, 16 ; down
			jmp main_loop_continue
		main_not_d:
		add r5, r4 -108
		jnz r5 main_not_l
		main_l:
			mov r4, -1 ; left
			jmp main_loop_continue
		main_not_l:
			mov r3, 0 ; fail
			mov r4, 0
			mov r7, 1 ; FAIL 1 - not wasd
	main_loop_continue:
	; now r4 has direction
	add r2, r2 r4
	; now we need to check for walls and out of bounds
	mov dptr, scratch_minus_1
	mov *dptr, r2
	mov dptr, scratch
	mov r4, *dptr
	jnz r4, out_of_bounds
	; we're in bounds, let's see if it's a wall
	add dptr, maze r2
	mov r4, *dptr

	; 8 bit only...
	mov dptr, scratch_minus_1
	mov *dptr, r4
	mov dptr, scratch
	mov *dptr, 0
	mov dptr, scratch_minus_1
	mov r4, *dptr
	
	add r4, r4 r4
	add dptr, is_nonprime r4
	mov r4, *dptr
	; if r4 is 1 (nonprime), we hit the wall
	jnz r4, hit_wall
	; else, we're good
	; now let's see if we're at the good position
	add r4, r1 1
	add dptr, negpositions r4

	mov r4, *dptr ; -target
	add r4, r4 r2
	jnz r4 not_at_target
	; we hit the target, so add one to target counter
	add r1, r1 1

	not_at_target:
	jmp main_loop

	hit_wall:
	mov r3, 0
	mov r7, 2 ; fail 2 - hit wall
	jmp main_loop
	
	out_of_bounds:
	mov r7, 4 ; fail 4 - out of bounds
	jmp halt ; fail instantly in that case

	

after_main_loop:

jnz r3 no_walls_breached
jmp fail

no_walls_breached:

add r4, r1 -9
jnz r4, targets_not_reached
jmp decrypt_flag

targets_not_reached:
mov r7, 3 ; fail 3 - targets not reached
jmp fail


; ======================================
decrypt_flag:

mov r0, 0
mov r1, 0
decrypt_loop:
	; compare r0 to flag length
	add r2, r0 minus_flag_len
	jnz r2, continue_decrypt_loop
	jmp decrypt_end
	continue_decrypt_loop:
	; now let's add appropriate values from password
	mov r3, 4
	mov r2, 0
	decrypt_char_loop:
		add r2, r2 r2
		add r2, r2 r2 ; r2 <<= 2
		
		add dptr, pass r1
		mov r4, *dptr
		add r5, r4 -117
		jnz r5 dec_not_u
		dec_u:
			; add 0
			jmp dec_char_loop_continue
		dec_not_u:
		add r5, r4 -114
		jnz r5 dec_not_r
		dec_r:
			; add 1
			add r2, r2 1
			jmp dec_char_loop_continue
		dec_not_r:
		add r5, r4 -100
		jnz r5 dec_not_d
		dec_d:
			; add 2
			add r2, r2 2
			jmp dec_char_loop_continue
		dec_not_d:
		add r5, r4 -108
		jnz r5 dec_not_l
		dec_l:
			; add 3
			add r2, r2 3
			jmp dec_char_loop_continue
		dec_not_l:
			; fail
			jmp fail

		dec_char_loop_continue:
		add r1, r1 1
		add r3, r3 -1
		jnz r3, decrypt_char_loop

	add dptr, enc_flag r0
	mov r3, *dptr ; r3 = enc[i]
	add dptr, flag r0
	add *dptr, r3 r2 ; flag[i] = enc[i] + key
	add r0, r0 1
	jmp decrypt_loop

decrypt_end:
add dptr, flag r0
mov *dptr, 0
jmp halt

fail:
mov dptr, flag
mov *dptr, 0
jmp halt

.equ is_nonprime 0x7000

.equ pass 0xe000
; pass will be provided by the user
.equ flag 0xe800
; flag will be decrypted here

.org 0xf000
maze:
.db 204 176 231 123 188 192 238 58 252 115 129 208 122 105 132 226 72 227 215 89 17 107 241 179 134 11 137 197 191 83 101 101 240 239 106 191 8 120 196 44 153 53 60 108 220 224 200 153 200 59 239 41 151 11 179 139 204 157 252 5 27 103 181 173 21 193 8 208 69 69 38 67 69 109 244 239 187 73 6 202 115 107 188 233 80 151 5 229 151 211 181 71 43 173 37 139 174 175 65 229 216 20 244 131 230 240 192 152 10 172 161 149 245 181 211 83 240 151 239 157 212 59 59 11 231 23 7 31 108 241 30 68 146 178 87 7 183 54 143 83 201 234 16 144 98 223 29 7 179 113 83 97 26 43 120 191 193 181 198 59 234 43 68 23 160 132 202 143 183 59 56 47 232 115 132 173 68 239 248 173 140 31 234 127 205 197 179 73 5 3 149 167 68 181 145 105 248 149 108 229 135 83 78 71 146 190 128 208 128 29 173 241 61 227 223 53 97 241 231 13 113 197 2 79 32 94 162 139 196 97 50 15 168 190 126 41 209 109 42 217 85 71 7 131 234 43 121 149 79 61 163 17 221 193 29 137
start:
.dw 17
negpositions:
.db -17 -125 -255 -81 -183 -83 -63 -241 -117 -31
enc_flag:
.db 158 255 161 38 20 59 104 96 107 199 52 196 10 27 109 140 201 71 118 101 50 116 95 226 37 114 50 116 98 10 185 129 110 198 23 227 197 102 125
.equ minus_flag_len -39
.equ passlength 254

.equ scratch 0xfff0
.equ scratch_minus_1 0xffef
.equ halt 0xfffe

