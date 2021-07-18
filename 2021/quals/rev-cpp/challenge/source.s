; Copyright 2021 Google LLC
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

rom 187 85 171 197 185 157 201 105 187 55 217 205 33 179 207 207 159 9 181 61 235 127 87 161 235 135 103 35 23 37 209 27 8 100 100 53 145 100 231 160 6 170 221 117 23 157 109 92 94 25 253 233 12 249 180 131 134 34 66 30 87 161 40 98 250 123 27 186 30 180 179 88 198 243 140 144 59 186 25 110 206 223 241 37 141 64 128 112 224 77 28

jmp main

return:
	not R
	mov Z, 1
	add R, Z
	add R, Z
	jz ret1, R
	add R, Z
	jz ret2, R
	add R, Z
	jz ret3, R
	error "BUG"
	halt
	; ...

; T, U, V, W, X, Y, Z are used in numerical subroutines
mul: ; calculates A *= B, returns to lab_R
	mov X, 1
	mov Y, 0
	mul_loop:
		jz mul_end, X
		
		mov Z, X
		and Z, B
		jz mul_dontadd, Z
		
		add Y, A

		mul_dontadd:
		add X, X
		add A, A
		jmp mul_loop

	mul_end:
	mov A, Y
	jmp return

	




main:

mov I, 0 ; index
mov M, 0 ; fib0
mov N, 1 ; fib1
mov P, 0 ; current sum
mov Q, 0 ; is bad
mainloop:
	mov B, 229
	add B, I
	jz mainend, B

	mov B, 128
	add B, I
	load A, B ; A = flag[i]
	;jz mainend, A ; break if zero

	load B, I ; B = multipliers[i]
	mov R, 1
	jmp mul
	ret1:
	; Now A = flag[i] * multipliers[i]

	mov O, M
	add O, N
	mov M, N
	mov N, O ; calculate new fibonacci

	add A, M ; A = flag[i] * multipliers[i] + fib(i)
	mov B, 32
	add B, I
	load C, B
	xor A, C ; A = (f[i]*m[i]+fib(i)) ^ x[i]

	add P, A ; P += A
	mov B, 64
	add B, I
	load A, B ; A = expected[i]
	xor A, P ; A = P^expected[i] (should be zero if good)
	or Q, A ; constant time compare... so you cannot just time side channel

	mov A, 1
	add I, A
	jmp mainloop
	
mainend:

jz main_ok, Q ; A = Q==0
error "INVALID_FLAG"
main_ok:
halt

ret2:
ret3:

















