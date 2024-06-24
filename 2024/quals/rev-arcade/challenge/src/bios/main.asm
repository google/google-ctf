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

    include "regdefs.asm"
    include "header.asm"

RAMSTART            	equ $100000   		; 68k work RAM
ADMIN_MODE_ON       	equ RAMSTART+10		; Define a variable to indicate the BIOS that Admin mode is ON.

USER            	equ $0122		; Location of USER subroutine where it should jump to.

    ; PC_START
    ; The M68k will mirror the bytes here into C00402.
    org $402
    bra         RESET

    org $444
    bra         SYSTEM_RETURN

    org $44a
    bra         SYSTEM_IO

    org $4C2
    bra         FIX_CLEAR

    org $4C8
    bra         LSP_1ST

RESET:
    move.b      #0,REG_DIPSW            ; Kick watchdog.
    move.w      #$2700,sr               ; Supervisor mode, disable all interrupts.
    move.w      #7,REG_IRQACK           ; Acknowledge all interrupts.
    move.w      #0,REG_LSPCMODE         ; Disable timer.
    move.b      #1,BIOS_MVS_FLAG        ; We're MVS.
    move.b      #0,BIOS_CREDIT_DEC1     ; No credits for P1.

    lea         $10F300,sp              ; Load stack pointer.

    move.b      #0,BIOS_USER_REQUEST    ; Tell the game to do an init.
    jmp         USER                    ; Jump to the game, the game should return through SYSTEM_RETURN

SYSTEM_RETURN:
    move.b      #0,REG_DIPSW            ; Kick watchdog.
    move.b      BIOS_USER_MODE,d0       ; Read the value from user mode, to know what they are doing.
    cmpi.b      #1,d0			; Compare it with Title/Demo ($01).
    bne         .demo                   ; If the game was doing Init (0) or Game (2), then ask to do Title/Demo now.

    ; If we're here then that means the game was doing Demo or Game.
    ; We need to tell the game to start again.
    move.b      #0,BIOS_USER_REQUEST    ; Ask for Init.
    jmp         USER

; Tell the game to do Title/Demo now.
.demo:
    move.b      #$80,BIOS_SYSTEM_MODE   ; Tell the game that it can use VBLANK.
    move.b      #2,BIOS_USER_REQUEST    ; Ask the game to do demo.
    move.b      #$1,REG_SWPROM          ; Switch the first $80 bytes with the cart's P ROM.
    move.b      #$1,REG_CRTFIX          ; Switch with the cart's S ROM and M1 ROM.
    move.b      #0,BIOS_STATCURNT       ; Clear select/start for all players.
    move.b      #0,BIOS_STATCHANGE      ; Clear select/start for all players.
    move.b      #0,BIOS_STATCURNT_RAW   ; Clear select/start for all players.
    move.b      #0,BIOS_STATCHANGE_RAW  ; Clear select/start for all players.
    move.w      #$2000,sr               ; Clear all flags and enable all interrupts.
    move.w      #7,REG_IRQACK           ; Acknowledge all interrupts.
    jmp         USER                    ; Blind jump to USER subroutine.

; Handle I/O from hardware and put it in well known RAM locations for the game to use.
; This _should_ be called during VBLANK, and _should_ assume the stack has been initialized and can be used.
SYSTEM_IO:
    movem.l     d0/d1,-(sp)		; Save the state of D0/D1.

    ; If we're on Admin mode, skip to get input. We shouldn't interrupt the game with coin or start.
    move.b      ADMIN_MODE_ON,d0
    tst.b       d0
    bne         .getInput

    ; Check if the user placed a coin.
    move.b      REG_STATUS_A,d0         ; Get the coin status.
    btst        #0,d0                   ; If bit 0 is cleared then a coin was inserted.
    beq         COIN_IN                 ; Jump to COIN_IN if a coin was inserted.

    ; Check if the game is running. If so we don't care to start a new game until this one finishes.
    move.b      BIOS_USER_MODE,d0       ; Get the value of the user mode.
    cmpi.b      #2,d0                   ; 2 is when the user is in Game mode.
    beq         .getInput               ; Skip to the input if the game is in Game mode.

    ; Check if the user pressed start.
    move.b      REG_STATUS_B,d0         ; Get the P1 start button.
    btst        #0,d0                   ; Check bit 0.
    bne         .getInput               ; If Start was not pressed, skip.         

    ; Check if the user has enough credits.
    move.b      BIOS_CREDIT_DEC1,d0     ; Load the amount of credits for P1.
    tst.b       d0                      ; Test if D0 is empty.
    beq         .getInput               ; Skip if there are no credits.

    ; At this point, the user pressed "start" and has enough credits.
    ; Call the Player Start Subroutine.
    move.b      #1,BIOS_START_FLAG      ; Indicate that P1 pushed start.
    move.w      #$2000,sr               ; Enable all interrupts.
    jmp         PLAYER_START            ; Blind jump to start the game. They should clear RAM and reset the stack.

; This subroutine gets the raw input from the machine and translates it to BIOS well known places.
.getInput:
    ; Update the previous.
    move.b      BIOS_P1CURRENT,d0       ; This is the current input for this frame.
    move.b      d0,BIOS_P1PREVIOUS      ; Move the current to previous. 
    
    ; Update the current.
    move.b      REG_P1CNT,d0            ; Get the current value of the player's input.
    not.b       d0                      ; REG_P1CNT is active low, so switch the logic.
    move.b      d0,BIOS_P1CURRENT       ; This is the current input for this frame.
    
    ; Update the change.
    ; We need this truth table:
    ; current previous change
    ;    0       0        0
    ;    0       1        0
    ;    1       0        1
    ;    1       1        0
    move.b      BIOS_P1PREVIOUS,d1      ; Load the previous. 
    eor.b       d0,d1                   ; XOR with the current.
    and.b       d1,d0                   ; Filter to only get the rising change.
    move.b      d0,BIOS_P1CHANGE        ; Save it to the changed inputs.

    movem.l     (sp)+,d0/d1		; Restore from stack.
    rts					; Return from subroutine.

; This subroutine will call the game's COIN sound, then the game _should_ call SYSTEM_RETURN so we ask
; the game to do a Title (should interrupt the Demo and play a Title indicating "press start").
COIN_IN:
    jsr         COIN_SOUND              ; Ask the game to play a coin sound.
    move.b      BIOS_CREDIT_DEC1,d0     ; Get the current credits.
    addi.b      #1,d0                   ; Add one.
    move.b      d0,BIOS_CREDIT_DEC1     ; Save it back.

    ; If the game told us it's running then don't interrupt it.
    move.b      BIOS_USER_MODE,d0
    cmpi.b      #2,d0			; #2 means the Game is in "Game mode".
    bne         .user			; If it's not in Game mode, then ask to do Title.
    
    movem.l     (sp)+,d0/d1		; Restore from stack.
    rts					; Return from subroutine.

; Tell the game to do TItle/Demo.
.user:
    move.b      #3,BIOS_USER_REQUEST    ; Ask the game to do title.
    move.w      #$2000,sr               ; Enable all interrupts.
    jmp         USER			; Blind jump to USER.

; BIOS handle of VBLANK, we don't care.
VBLANK:
    rte

; BIOS handle of Timer, we don't care.
TIMER_INTERRUPT:
    move.b      #2,REG_IRQACK           ; Acknowledge the interrupt.
    rte

; BIOS handle of system interrupt, we don't care.
SYSTEM_INT1:
    move.b      #4,REG_IRQACK           ; Acknowledge the interrupt.
    rte                                 ; Return.

    include "clear_screen.asm"

; Message to the users that run "strings" on this ROM. This will appear byte-swapped.
    dc.b    "Did you know that the m68k is big endian?"

