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

; Interrupt handlers. These are based from $300 onwards.
; header.asm already defined the interrupts to jump to these locations.
	org $300
TIMER_CALLBACK		equ RAMSTART+$a0
; VBLANK will be calle right before drawing the frame, which will happen ~60 times per second.
; It's the time between moving the beam from the lower right corner to the upper left corner.
VBLANK:
	btst    #7,BIOS_SYSTEM_MODE	        ; Check if the system ROM wants to take care of the interrupt
	bne     .handle_vblank		        ; No: jump to .handle_vblank
	jmp     SYS_INT1		            ; Yes: jump to system ROM, we shouldn't handle this VBLANK.
.handle_vblank:
	move.w  #4,REG_IRQACK	            ; Acknowledge v-blank interrupt
	move.b	d0,REG_DIPSW	            ; Kick watchdog
	jsr		SYS_IO						; Get the input from the user.
    move.b	#1,VBLANK_PASS				; VBLANK done.
	rte			                        ; Return from interrupt
; Interrupt when the time reached 0, we're not using this so
; just return.
TIMER_INT:
	move.w	#2,REG_IRQACK	            ; Acknowledge timer interrupt
    bsr     .handle_timer
	rte                                 ; Return from interrupt
.handle_timer:
	move.l	a0,-(sp)
	lea		TIMER_CALLBACK,a0			; Load the address where we need to jump to.
	move.l	(a0),a0
	jsr		(a0)						; Jump to subroutine.
	move.l	(sp)+,a0
    rts                                 ; We're not doing anything with the timer, so go back.
; User subroutine: https://wiki.neogeodev.org/index.php?title=USER_subroutine
; The BIOS will jump here asking for a specific command stored in BIOS_USER_REQUEST:
; 0:StartupInit, 1:Eyecatcher, 2:Demo, 3:Title
USER:
	move.b	d0,REG_DIPSW			    ; Kick watchdog, to make sure the game doesn't reset.
	clr.l	d0						    ; Clear register D0.
	move.b	BIOS_USER_REQUEST,d0	    ; Put BIOS_USER_REQUEST (byte) in D0
	
    ; We need to multiply D0, because the addresses we declared in JT_USER are long words, so 4 bytes each.
	lsl.b	#2,d0			            ; D0 *= 4
	lea	    JT_USER,a0			        ; Put the address of JT_USER in A0
	movea.l	(a0,d0),a0		            ; Read from jump table
	jsr	    (a0)				        ; Push this address to the stack and jump, wait until the game returns back.
	jmp	    SYS_RETURN			        ; Tell the system ROM that we're done by jumping to BIOSF_SYSTEM_RETURN (declared as SYS_RETURN here)
; This jump table comes handy when picking where to jump to depending on what the BIOS wants the game to do.
JT_USER:
	dc.l    StartupInit
	dc.l	EyeCatcher
	dc.l	Demo
	dc.l	Title
WaitForVBLANK:
    movem.l     d1/a0,-(sp)
.loop:
    move.b	    #0,REG_DIPSW
    lea         VBLANK_PASS,a0          ; Load the value of VBLANK_PASS
    move.b      (a0),d1
    tst.b       d1                      ; Check if it's zero.
    beq         .loop                   ; Go back if we didn't had a VBLANK yet.
    move.b      #0,(a0)                 ; Reset VBLANK_PASS
    movem.l     (sp)+,d1/a0
    rts                                 ; We're done waiting.