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

; Main entrypoint for the P-ROM file.
; Much of this code comes from https://wiki.neogeodev.org/index.php?title=Hello_world_tutorial
; which is licensed under "Public Domain": https://creativecommons.org/publicdomain/

; Include out handy register defines so we don't have to remember which register is at which address.
	include "regdefs.asm"
	
; Include the header so our game is recognized by the system ROM.
	include "header.asm"

; Include the interrupt handlers.
	include "interrupt_handlers.asm"

; Displays the game title, used to lure people into play the game. 
EyeCatcher:
	jmp		SYS_RETURN
; Called when a coin is inserted, should wait for the user to press START or a timer countdown.
Title:
	move.b  #1,REG_TIMERSTOP				; Stop the timer.
	lea     PrintPressStart,a0				; Switch timer callbacks to "Press

    move.l  a0,TIMER_CALLBACK               ; When timer interrupts, print the label.
    move.w  #$2d,REG_TIMERHIGH           
    move.w  #$c6c0,REG_TIMERLOW

	move.b  	#01,BIOS_USER_MODE				; We're doing Demo/Title
	jsr			Game
	jmp			SYS_RETURN

; Called once at the start of the game. Used to clear RAM, initialize ranking, I/O and display.
StartupInit:
	move.b	#0,BIOS_USER_MODE				; Tell BIOS we're doing init.
	move.b	d0,REG_DIPSW					; Kick watchdog, to make sure the game doesn't reset.
	move.w	#$0030,REG_LSPCMODE				; Enable timer and reload when we write to REG_TIMERLOW.
	move.w  #7,REG_IRQACK           		; Clear all interrupts
	jmp		SYS_RETURN

; Start the game.
Demo:
	move.b  #01,BIOS_USER_MODE				; We're doing Demo/Title
	move.b	#3,REG_SOUND					; Tell the Z80 to restart.

	move.w  #7,REG_IRQACK           		; Clear all interrupts
	
	; Clear RAM and set up our stack.
	lea 	RAMSTART+$F300,sp				; Set the start of our stack, this will grow downwards.
	lea		RAMSTART,a0						; Load the start of our work RAM (64 KiB).
	move.l	#($F300/32)-1,d7				; RAM is $F300 long, so count the amount of long words we have to clear.
.clear_ram:
	move.l 	#0,(a0)+						; Clear contents of a0 in memory, then move forward.
	move.l 	#0,(a0)+
	move.l 	#0,(a0)+
	move.l 	#0,(a0)+
	move.l 	#0,(a0)+
	move.l 	#0,(a0)+
	move.l 	#0,(a0)+
	move.l 	#0,(a0)+
	dbra	d7,.clear_ram					; If not zero then jump back to loop.

	jsr		SYS_LSP_1ST						; Clear sprites.
	jsr		SYS_FIX_CLEAR					; Clear the Fix Layer.
	jsr		InitPalettes

	lea     PrintInsertCoin,a0				; Switch timer callbacks to "Insert Coin".

    move.l  a0,TIMER_CALLBACK               ; When timer interrupts, print the label.
    move.w  #$2d,REG_TIMERHIGH           
    move.w  #$c6c0,REG_TIMERLOW

; Game initialization done here. We now jump to the main() function of our game.
	jsr		Game							; Jump to our game code, we shouldn;t return unless there's a problem or game over.
	jmp		SYS_RETURN

; Infinite loop, here to protect the CPU from executing the bytes below.
.hang
	move.b	d0,REG_DIPSW
	bra 	.hang

; Functions
	include "print.asm"
	include "print_google_logo.asm"
	include "print_google_logo_red.asm"
	include "print_background.asm"
	include "print_chest_left.asm"
	include "print_chest_right.asm"
	include "print_robot.asm"
	include "print_trash_message.asm"
	include "print_key_message.asm"
	include "game.asm"
	include "print_flag.asm"
	include "blink.asm"
	include "blink_flag.asm"
	include "change_selected.asm"
	include "change_selected_flag.asm"
	include "coin_message.asm"
	include "alternative_admin_panel.asm"
	include "print_key.asm"
	include "init_palettes.asm"
	include "player_start.asm"
	include "fake_game.asm"
	include "strings.asm"
