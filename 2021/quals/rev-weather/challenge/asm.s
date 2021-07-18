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

entry:
call main
%s
endfun

dexor:
mov r3, [r1]
xor r3, r0
mov [r1], r3
add r1, 4
mov r3, r1
sub r3, r2
call- dexor, r3
endfun

main:
mov r0, [city]
and r0, 255
mov r1, r0
shl r1, 8
or r0, r1
mov r1, r0
shl r1, 16
or r0, r1

mov r1, main2
mov r2, endcode
call dexor
mov [flag], 1701736302 ; "none"
mov r0, [main2]
and r0, 255
sub r0, 37
call0 main2, r0
endfun

.org 200
main2:
; calculate some primes
mov r4, primes
mov r0, 13200 ; STARTING PRIME
call primeloop
;mov r0, 0
;call printprimes
mov r0, 0
call xorprimeaddcollatz
;mov r0, 0
;call printcity

call check
call0 goodcity, r0

endfun



setnonprime:
mov r1, 0
endfun

checkprimeloop:
mov r3, r0
mod r3, r2
call0 setnonprime, r3
add r2, 1
mov r3, r2
mul r3, r3
sub r3, r0
sub r3, 1
call- checkprimeloop, r3
endfun

newprime:
mov [r4], r0
add r4, 2
endfun

primeloop:
mov r1, 1 ; by default, prime
mov r2, 2 ; iterator
call checkprimeloop
call+ newprime, r1
add r0, 1
mov r1, 13600 ; ENDING PRIME
sub r1, r0
call+ primeloop, r1
endfun

;printprimes:
;mov r2, r0
;mul r2, 2
;add r2, primes
;mov r2, [r2]
;and r2, 65535
;debug r2, r2
;add r0, 1
;mov r1, 50
;sub r1, r0
;call+ printprimes, r1
;endfun

collatzreturn0:
mov r0, 0
endfun

collatzdiv2:
div r0, 2
endfun

collatzdiv3:
mul r0, 3
add r0, 1
endfun

collatznormal:
mov r1, r0
mod r1, 2
call0 collatzdiv2, r1
call+ collatzdiv3, r1
call collatz
add r0, 1
endfun

; r0 - argument, returns also in r0
; trashes r1
collatz:
mov r1, r0
sub r1, 1
call0 collatzreturn0, r1
call+ collatznormal, r1
endfun

;collatzloop:
;mov r2, r0
;call collatz
;mov r3, r2
;mul r3, 4
;add r3, primes
;mov [r3], r0
;mov r0, r2
;add r0, 1
;mov r1, 25 ; ENDING collatz
;sub r1, r0
;call+ collatzloop, r1
;endfun

;printcity:
;mov r2, r0
;add r2, city2
;mov r2, [r2]
;and r2, 255
;debug r2, r2
;add r0, 1
;mov r1, 50
;sub r1, r0
;call+ printcity, r1
;endfun

xorprimeaddcollatz:
mov r2, r0
add r2, city
mov r4, [r2]
and r4, 255
;debug r4, r4
call+ reallyxor, r4
endfun

reallyxor:
mov r2, r0
mul r2, 2
add r2, primes
mov r2, [r2]
and r2, 255
xor r4, r2
add r0, 1
mov r2, r0
call collatz
add r4, r0
and r4, 255
mov r0, r2
sub r2, 1
add r2, city2
mov [r2], r4
call xorprimeaddcollatz
endfun

goodcity:
; Decrypt flag:
mov r0, 123456789
mov r1, 0
add r1, city
mov r1, [r1]
xor r0, r1
mov r2, 0
add r2, 846786818
xor r2, r0
mov r1, 0
add r1, flag
mov [r1], r2
mov r1, 4
add r1, city
mov r1, [r1]
xor r0, r1
mov r2, 0
add r2, 1443538759
xor r2, r0
mov r1, 4
add r1, flag
mov [r1], r2
mov r1, 8
add r1, city
mov r1, [r1]
xor r0, r1
mov r2, 0
add r2, 1047515510
xor r2, r0
mov r1, 8
add r1, flag
mov [r1], r2
mov r1, 12
add r1, city
mov r1, [r1]
xor r0, r1
mov r2, 0
add r2, 359499514
add r2, 1724461856
xor r2, r0
mov r1, 12
add r1, flag
mov [r1], r2
mov r1, 16
add r1, city
mov r1, [r1]
xor r0, r1
mov r2, 0
add r2, 241024035
xor r2, r0
mov r1, 16
add r1, flag
mov [r1], r2
mov r1, 20
add r1, city
mov r1, [r1]
xor r0, r1
mov r2, 0
add r2, 222267724
xor r2, r0
mov r1, 20
add r1, flag
mov [r1], r2
mov r1, 24
add r1, city
mov r1, [r1]
xor r0, r1
mov r2, 0
add r2, 844096018
xor r2, r0
mov r1, 24
add r1, flag
mov [r1], r2

endfun

check:
; Check flag
mov r0, 0
mov r1, 0
add r1, city2
mov r1, [r1]
mov r2, 0
add r2, 1374542625
add r2, 1686915720
add r2, 1129686860
xor r1, r2
or r0, r1
mov r1, 4
add r1, city2
mov r1, [r1]
mov r2, 0
add r2, 842217029
add r2, 1483902564
xor r1, r2
or r0, r1
mov r1, 8
add r1, city2
mov r1, [r1]
mov r2, 0
add r2, 1868013731
xor r1, r2
or r0, r1
mov r1, 12
add r1, city2
mov r1, [r1]
mov r2, 0
add r2, 584694732
add r2, 1453312700
xor r1, r2
or r0, r1
mov r1, 16
add r1, city2
mov r1, [r1]
mov r2, 0
add r2, 223548744
xor r1, r2
or r0, r1
mov r1, 20
add r1, city2
mov r1, [r1]
mov r2, 0
add r2, 1958883726
add r2, 1916008099
xor r1, r2
or r0, r1
mov r1, 24
add r1, city2
mov r1, [r1]
mov r2, 0
add r2, 1829937605
add r2, 1815356086
add r2, 253836698
xor r1, r2
or r0, r1
endfun

endcode:
endfun

.org 4096
city:
.org 4500
city2:
.org 5000
primes:
.org 6144
flag:
