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

X_RAM           equ RAMSTART+20
Y_RAM           equ RAMSTART+22
SECRET_BRANCH   equ RAMSTART+$100

StartGame:
    move.b	    #0,REG_DIPSW
    move.b      #1,REG_TIMERSTOP
    jsr		    SYS_LSP_1ST						        ; Clear sprites.
    jsr         SYS_FIX_CLEAR                           ; Clear the screen.
    move.w      #BLACK,BACKDROP                         ; Change background to black.
    ; Print all the sprites at their starting position.
    jsr         PrintBackground
    jsr         PrintChestLeft
    jsr         PrintChestRight
    jsr         PrintRobot
    ; Set MOD to $200, so its moved from SCB3 to SCB4 on each write.
    move.w      #$200,REG_VRAMMOD
    nop
; Game loop
; Check for input every VBLANK and move the robot.
.loop:
    move.b	    #0,REG_DIPSW                                ; Watchdog
    jsr         UpdateRobotPosition                         ; Update the Robot's position.
    jsr         PrintMessages
    jsr         WaitForVBLANK                           ; Wait until VBLANK is done, so IO is done.
    bra         .loop
UpdateRobotPosition:
    movem.l     d0-d2,-(sp)
    move.w      #(SCB3+ROBOT_OFFSET),REG_VRAMADDR       ; Set address of the Robot sprite.
    nop
    ; Get y
    ; Up -> 11111110
    clr.l       d0
    clr.l       d1
    move.b      REG_P1CNT,d0                            ; Get this frame's P1 position.
    not.b       d0                                      ; Make it active high.
    ; Update Y position.
    andi.b      #1,d0                                   ; Mask to get the Right input.
    move.w      Y_RAM,d1                                ; Load the current X position.
    add.w       d0,d1                                   ; Add the movement.
    cmp         #$3af,d1
    bge         .skipUp                                 ; Skip if the player reached the top.
    move.w      d1,Y_RAM                                ; Move it back to RAM.
.skipUp:
    ; Down -> 11111101
    clr.l       d0
    clr.l       d1
    move.b      REG_P1CNT,d0                            ; Get this frame's P1 position.
    not.b       d0                                      ; Make it active high.
    ; Update Y position.
    andi.b      #2,d0                                   ; Mask to get the Right input.
    lsr.b       #1,d0                                   ; Move that bit to the LSB.
    move.w      Y_RAM,d1                                ; Load the current X position.
    sub.w       d0,d1                                   ; Add the movement.
    cmp         #$340,d1
    ble         .skipDown
    move.w      d1,Y_RAM                                ; Move it back to RAM.
.skipDown:
    ; Get x
    ; Right -> 11110111
    clr.l       d0
    clr.l       d1
    move.b      REG_P1CNT,d0                            ; Get this frame's P1 position.
    not.b       d0                                      ; Make it active high.
    ; Update X position.
    andi.b      #8,d0                                   ; Mask to get the Right input.
    lsr.b       #3,d0                                   ; Move that bit to the LSB.
    move.w      X_RAM,d1                                ; Load the current X position.
    add.w      d0,d1                                   ; Add the movement.
    cmp         #$f1,d1
    bge         .skipRight
    move.w      d1,X_RAM                                ; Move it back to RAM.
.skipRight:
    ; Left -> 11111011
    clr.l       d0
    clr.l       d1
    move.b      REG_P1CNT,d0                            ; Get this frame's P1 position.
    not.b       d0                                      ; Make it active high.
    ; Update X position.
    andi.b      #4,d0                                   ; Mask to get the Right input.
    lsr.b       #2,d0                                   ; Move that bit to the LSB.
    move.w      X_RAM,d1                                ; Load the current X position.
    sub.w       d0,d1                                   ; Add the movement.
    cmp         #$2b,d1
    ble         .skipLeft
    move.w      d1,X_RAM                                ; Move it back to RAM.
.skipLeft:
    ; Write y
    clr.l       d1
    move.w      Y_RAM,d1
    lsl.w       #7,d1
    addi.w      #ROBOT_H,d1
    move.w      d1,REG_VRAMRW
    nop
    nop
    ; Write x
    clr.l       d1
    move.w      X_RAM,d1
    lsl.w       #7,d1
    move.w      d1,REG_VRAMRW
    nop 
    nop
    ; Done
    movem.l     (sp)+,d0-d2
    rts
PrintMessages:
    movem.l     d0,-(sp)
    move.b      REG_P1CNT,d0
    andi.b      #$10,d0                 ; Mask the A button.
    tst.b       d0
    bne         .done                   ; If this is not zero, then A was not pressed.
    ; A button pressed, check if the robot is within either chest.
    move.w      Y_RAM,d0
    cmpi.w      #(CHEST_LEFT_Y-10),d0
    blo         .done                   ; Too far away.
    move.w      X_RAM,d0
    cmpi.w      #(CHEST_LEFT_X+32),d0
    bge         .leftTooFar             ; Too far away.
    ; In the zone, print the message.
    cmpi.b      #$87,(SECRET_BRANCH)
    bne         .printTrash
    jsr         PrintKeyMessage
    bra         .done

.leftTooFar:
    cmpi.w      #(CHEST_RIGHT_X-32),d0
    ble         .done
    cmpi.b      #$87,(SECRET_BRANCH)
    bne         .printTrash
    jsr         PrintKeyMessage
    bra         .done

.printTrash:
    jsr         PrintTrashMessage
    bra         .done
.done:
    movem.l     (sp)+,d0
    rts