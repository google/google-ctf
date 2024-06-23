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

; Secret (kind of) admin panel where it shows the flag result encrypted.

INPUT_LOCATION           equ FIXMAP+(4*32)+7
PLAYING_SOUND            equ RAMSTART+1
Z80_ANSWER_RAM           equ RAMSTART+2
MANAGING_INPUT           equ RAMSTART+3

AdminGameMode:
    ; Clear the screen.
    jsr		        SYS_LSP_1ST						        ; Clear sprites.
    jsr             SYS_FIX_CLEAR                           ; Clear the screen
    jsr             ClearInputBuffer

    ; Empty the input read buffer. Wait 3 VBLANK so input is zero.
    clr.l           d0
    move.b          #6,d0
.emptyInputBUffer:
    move.b	        #0,REG_DIPSW
    jsr             WaitForVBLANK
    dbra            d0,.emptyInputBUffer

    ; Clear the BIOS input.
    move.b          #0,BIOS_P1CURRENT
    move.b          #0,BIOS_P1PREVIOUS

    ; Clear the lock for playing sound.
    move.b          #0,PLAYING_SOUND

    ; Print the initial layout.
    move.w          #MIDGREEN,BACKDROP                      ; Change background to midgreen.
    jsr             PrintGoogleLogoRed                      ; Print the Google CTF logo.
    jsr             PrintAdminPanel                         ; Print a blinking start label.
    jsr             PrintUserMessage                        ; Print message to the user.

; Here we hang in an infinite loop.
; We need to get the input from the user, then do two things:
; * Print the Fix Map tile on screen.
; * Send the byte to the Z80 CPU, this will encrypt and play a sound. We should tell VBLANK that this is happening.
.hang:
    move.b	        #0,REG_DIPSW	                        ; Kick watchdog

    ; If a sound is being played, skip input.
    move.b          PLAYING_SOUND,d0                        ; Load the value of PLAYING_SOUND from memory.
    tst.b           d0                                      ; Check if it's 0.
    bne             .waitForBLANK                           ; Skip input if there's a sound playing.

    jsr             PrintInputFlag                          ; Print the input from the user (the flag).

    ; If Current input is not zero, skip.
    ; This means that the player is currently sending inputs.
    move.b          BIOS_P1CURRENT,d0
    tst.b           d0
    beq             .checkPreviousInput

    ; If we're here then the current input is not zero, and needs to be handled.

    ; first check if the user was previously holding buttons.
    move.b          MANAGING_INPUT,d0                       ; Load the managing input variable.
    tst.b           d0                                      ; Check if this is zero.
    bne             .skipArrayPush

    ; The user was not holding buttons, so mark the byte and push the array down.
    move.b          #1,MANAGING_INPUT                       ; Flag that the user is currently managing input.
    ; Push the array down.
    ; for (i = len(input_array)-1;i>0;i--)
    ;   input_array[i+1] = input_array[i]
    clr.l           d1
    move.b          #31,d1                                  ; Input array length is 32 bytes, so that minus the first input.
    lea             INPUT_ARRAY+31,a0
    lea             INPUT_ARRAY+32,a1
.loop:                          
    move.b          -(a0),-(a1)
    dbra            d1,.loop

.skipArrayPush:
    ; Write current byte to INPUT_ARRAY[0]
    move.b          BIOS_P1CURRENT,d0
    move.b          d0,(INPUT_ARRAY)

    bra             .waitForBLANK                           ; Skip checking the previous input, not necessary.

.checkPreviousInput:
    ; Ok so there are no inputs from the user. Check if the previous inputs
    ; are zero, if so, skip.
    move.b          BIOS_P1PREVIOUS,d0
    tst.b           d0
    beq             .waitForBLANK

    ; At this point the user is not currently touching input, but the previous frame had input.
    ; So that means they just released the button. We need to capture this input and print it.
    jsr             SendByteToZ80
    move.b          #0,MANAGING_INPUT                       ; Flag that the user is done with input.

.waitForBLANK:
    jsr             WaitForVBLANK                           ; Wait for VBLANK
    bra             .hang

; Simple routine to print the input 
PrintInputFlag:
    movem.l         d0/d1/a0,-(sp)

    lea             INPUT_ARRAY,a0                          ; Load the text we want to write.
    move.w          #INPUT_LOCATION,d0                      ; Print at the higher part of the screen
    move.w          #$2100,d1                               ; Palette 2, second bank of fix map tiles.
	jsr	            Print

    movem.l         (sp)+,d0/d1/a0
    rts                                                     ; Return from subroutine.

SendByteToZ80:
    movem.l         d0,-(sp)

    move.b          #1,PLAYING_SOUND                        ; Save a 1 here so VBLANK knows that it should not get input until this is cleared.
    ; Send the byte to Z80 for encryption
    move.b          BIOS_P1PREVIOUS,d0                      ; Load the previous byte.
    move.b          d0,REG_SOUND
    move.l          #$ffff,d0                               ; A lot has to happen (TEA encryption, play a sound), so hang here for a while.
.loop:
    move.b	        #0,REG_DIPSW                            ; Kick watchdog so we don't get reset.
    dbra            d0,.loop
    move.b          #0,PLAYING_SOUND                        ; Done playing sound.
    
    movem.l         (sp)+,d0
    rts

; This prints "Admin Panel" and sets a timer to clear it.
; The clear function will do the same, set a timer to write "Admin Panel".
; So this effectively makes a blinking effect.
PrintAdminPanel:
    movem.l         d0/d1/a0,-(sp)                          ; Push to the stack.

    ; Print "Admin Panel" to the fix layer.
    lea             AdminPanel,a0                           ; Load the text we want to write.
    move.w          #FIXMAP+(14*32)+28,d0                   ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
    move.w  REG_VRAMADDR,-(sp)                              ; We need to save these values to the stack, because there's another function that can use them.
    move.w  REG_VRAMMOD,-(sp)
    jsr	            Print
    move.w  (sp)+,REG_VRAMMOD
    move.w  (sp)+,REG_VRAMADDR

    ; Load timer and callback.
    lea             PrintEmpty,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.

    movem.l (sp)+,d0/d1/a0                                  ; Restore from stack.
    rts

; This print an empty string the same size of "Admin Panel"
; The "Admin Panel" print function is loaded as callback when the timer ends.
PrintEmpty:
    movem.l         d0/d1/a0,-(sp)                          ; Push to the stack.

    lea             Empty,a0                                ; Load the text we want to write.
    move.w          #FIXMAP+(14*32)+28,d0                   ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
    move.w  REG_VRAMADDR,-(sp)                              ; We need to save these values to the stack, because there's another function that can use them.
    move.w  REG_VRAMMOD,-(sp)
	jsr	            Print                                   ; Effectively print blanks.
    move.w  (sp)+,REG_VRAMMOD
    move.w  (sp)+,REG_VRAMADDR

    ; Load timer and callback.
    lea             PrintAdminPanel,a0                      ; Load the callback address.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, print the label.
    move.w          #$0d,REG_TIMERHIGH           
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.

    movem.l         (sp)+,d0/d1/a0                          ; Restore from stack.
    rts

; Simple function to print "InputTheFlag" above.
PrintUserMessage:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.

    lea             InputTheFlag,a0                            ; Load the text we want to write.
    move.w          #FIXMAP+(13*32)+5,d0                    ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
	jsr	            Print

    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts                                                     ; Return from subroutine.

ClearInputBuffer:
    movem.l         d0/a0,-(sp)

    ; Clear the input buffer.
    clr.l           d0
    move.b          #32,d0                                  ; Input array length is 32 bytes, so that minus the first input.
    lea             INPUT_ARRAY,a0
.loop:                          
    move.b          #0,(a0)+
    dbra            d0,.loop

    movem.l         (sp)+,d0/a0
    rts