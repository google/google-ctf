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

PLAYING_SOUND            equ RAMSTART+1
ADMIN_MODE_ON            equ RAMSTART+$10
KEY_LOCATION             equ RAMSTART+$20
TX_COUNT                 equ RAMSTART+$30
INPUT_BUFFER             equ RAMSTART+$40
VBLANK_WAIT              equ RAMSTART+$61
INPUT_SELECTION          equ RAMSTART+$62

AdminGameMode:
    move.b	        #0,REG_DIPSW
    move.b          #1,ADMIN_MODE_ON                        ; Let the BIOS know that we're on Admin mode.
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

    ; Print the initial layout.
    move.w          #MIDGREEN,BACKDROP                      ; Change background to midgreen.
    jsr             InitDecrypted                           ; Initialize decrypted buffer.
    jsr             PrintGoogleLogoRed                      ; Print the Google CTF logo.
    jsr             PrintUserInstructions                   ; Print the instructions to the user.
    jsr             PrintKeyLabel                           ; Print a label that says "key".
    jsr             PrintFlagLabel                          ; Print "Decrypted:" label.
    jsr             PrintInputFlag                          ; Print the input flag.
    jsr             PrintKey                                ; Print the key used to decrypt.
    jsr             BlinkKey                                ; Start the blink interrupt callback.

    move.b          #0,TX_COUNT
    move.b          #0,VBLANK_WAIT
    move.b          #0,INPUT_SELECTION                      ; 0 for the key, 1 for the flag.
    lea             KEY_LOCATION+16,a1

; Main loop of Admin mode
.hang:
    move.b	        #0,REG_DIPSW	                        ; Kick watchdog

    ; If the count is not zero then we're transmitting the key and flag to Z80. 
    move.b          TX_COUNT,d0
    tst.b           d0
    bne             .tx

    jsr             ClearDecrypting
    jsr             UpdateSelectedLocation
    jsr             CheckStartPress
    jsr             CheckSwitch

    tst.b           (INPUT_SELECTION)
    bne             .updateFlagSelectedValue
    jsr             UpdateSelectedValue
    bra             .waitForBLANK
.updateFlagSelectedValue:
    jsr             UpdateFlagSelectedValue
    
    bra             .waitForBLANK

.tx:
    move.b          -(a1),REG_SOUND

    ; Decrement the TX count
    move.b          TX_COUNT,d0
    subi.b          #1,d0
    move.b          d0,TX_COUNT

    ; If the count is equal to 32 then switch to transmit the plaintext.
    cmpi.b           #32,d0
    beq             .switchToFlag

    ; If the count is not zero then wait for VBLANK
    tst.b           d0
    bne             .waitForBLANK

    ; The count is zero, we're done transmitting the key.
    ; Reset the pointer to the key location.
    lea             KEY_LOCATION+16,a1

    ; Set the receive buffer count, so on next VBLANK we receive the decrypted bytes.
    move.b          #90,VBLANK_WAIT                         ; Wait for 20 VBLANK, so we give time to decrypt.
    bra             .waitForBLANK

.switchToFlag:
    lea             INPUT_BUFFER+32,a1

.waitForBLANK:
    clr.l           d0
    move.b          VBLANK_WAIT,d0
.loop:
    move.b	        #0,REG_DIPSW
    jsr             WaitForVBLANK                           ; Wait for VBLANK
    dbra            d0,.loop

    move.b          #0,VBLANK_WAIT
    bra             .hang

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

    movem.l (sp)+,d0/d1/a0                                  ; Restore from stack.
    rts

; Function to print the instructions on screen for the user.
PrintUserInstructions:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.

    lea             PressStartToDecrypt,a0                  ; Load the text we want to write.
    move.w          #FIXMAP+(10*32)+25,d0                    ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
	jsr	            Print

    lea             PressAToSwitchInputs,a0                  ; Load the text we want to write.
    move.w          #FIXMAP+(9*32)+27,d0                    ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
	jsr	            Print

    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts                                                     ; Return from subroutine.

; Print a label that says "InputTheKey".
PrintKeyLabel:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.

    lea             InputTheKey,a0                          ; Load the text we want to write.
    move.w          #FIXMAP+(14*32)+21,d0                    ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
	jsr	            Print

    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts

; Print a label that says "Input the flag:".
PrintFlagLabel:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.

    lea             InputTheFlag,a0                          ; Load the text we want to write.
    move.w          #FIXMAP+(13*32)+4,d0                    ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
	jsr	            Print

    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts

PrintDecrypting:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.

    lea             Decrypting,a0                          ; Load the text we want to write.
    move.w          #FIXMAP+(13*32)+13,d0                    ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
	jsr	            Print

    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts

ClearDecrypting:
    movem.l         d0/d1/a0,-(sp)                          ; Save registers.

    lea             Spaces,a0                          ; Load the text we want to write.
    move.w          #FIXMAP+(13*32)+13,d0                    ; Print at the lower part of the screen.
    move.w          #$2000,d1                               ; Palette 2.
	jsr	            Print

    movem.l         (sp)+,d0/d1/a0                          ; Restore registers.
    rts

; Clear the input buffer, so we don't display random characters.
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

InitFlag:
    dc.l    $80402010,$3c3c3c3c,$3c3c3c3c,$3c3c3c3c,$3c3c3c3c,$3c3c3c3c,$3c3c3c3c,$3c3c3c01

; Check if the user pressed start.
CheckStartPress:
    movem.l         d0,-(sp)
    ; Check if the user pressed start.
    move.b      REG_STATUS_B,d0         ; Get the P1 start button.
    btst        #0,d0                   ; Check bit 0.
    bne         .done                   ; If Start was not pressed, skip.

    move.b          #$30,TX_COUNT
    jsr             PrintDecrypting

.done:
    movem.l         (sp)+,d0
    rts

; Check if the user pressed A.
CheckSwitch:
    movem.l         d0/a0,-(sp)

    move.b      BIOS_P1CHANGE,d0
    btst        #4,d0
    beq         .done                   ; If A was not pressed, skip.

    ; Switch inputs.
    move.b      INPUT_SELECTION,d0
    not         d0
    move.b      d0,INPUT_SELECTION

    tst.b       d0
    beq         .switchToKey

    jsr             PrintKey
    ; Load timer and callback.
    lea             BlinkFlag,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.
    bra             .done
; Switch to the key input.
.switchToKey:
    jsr             PrintInputFlag
    ; Load timer and callback.
    lea             BlinkKey,a0                           ; Callback is the Empty function.
    move.l          a0,TIMER_CALLBACK                       ; When timer interrupts, clear the label.
    move.w          #$0d,REG_TIMERHIGH                      ; I don't know how much time this is, but it looks nice.
    move.w          #$c6c0,REG_TIMERLOW                     ; At this point the timer got triggered.

.done:
    movem.l         (sp)+,d0/a0
    rts
