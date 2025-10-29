; The main file for the game.
; It displays a game under development (so I don't have to finish up a game), but also a (easily spotted)
; hidden "flag panel".

INCLUDE "../third_party/rev-cgb/hardware.inc"
INCLUDE "src/rom/locations.inc"
INCLUDE "src/rom/macros.inc"

; We jump here from the Header.
SECTION "Entry Point", ROM0[$150]
EntryPoint:
	EXPORT EntryPoint

; Turn the LCD off, we're going to copy stuff to VRAM.
	call WaitForVBlank
	xor a
	ld [rLCDC], a

; Clear OAM. This is safe at VBLANK but we can do it now since the PPU is off.
	ld		hl,_OAMRAM
	ld		bc, $00a0
	call 	ClearRAM

; Clear VRAM0.
	ld		hl,_VRAM
	ld		bc, $0040
	call 	ClearRAM

; Load all the tiles to VRAM. These are located in ROM bank 1, so we need to first switch there.

; Switch to ROM bank 1.
	ld	a, 1
	ld	[rROMB0], a

; Copy the tiles to VRAM ($8000).
	ld de, Tiles
	ld hl, _VRAM
	ld bc, Tiles.end - Tiles
	call	CopyToRAM

; Copy the Splash screen tilemap, this is the begining of the game.
	ld de, SplashTilemap
	ld hl, _SCRN0
	ld bc, SplashTilemap.end - SplashTilemap
	call 	CopyToRAM

	; Turn the LCD on: https://gbdev.io/pandocs/LCDC.html#ff40--lcdc-lcd-control
	ld a, LCDCF_ON | LCDCF_WIN9C00 | LCDCF_WINOFF | LCDCF_BLKS | LCDCF_BG9800 | LCDCF_OBJ8 | LCDCF_OBJON | LCDCF_PRION
	ld [rLCDC], a

; Load the VBLANK counter
	ld		a, VBLANK_COUNTER_START
	ld		[VBLANK_COUNTER_ADDR], a

; Load the BG counter
	ld		a, 128
	ld		[BG_COUNTER_ADDR], a

; Init audio.
	; Turn on the Audio, the rest of the bits are read-only.
    ld      a, AUDENA_ON
    ld      [rAUDENA], a

    ; Audio panning, either to left or right. We just make all channels the same volume
    ; on each side.
	ld		a, $ff
	ld		[rAUDTERM], a

    ; Master volume and external audio. Just make everything max.
    ; https://gbdev.io/pandocs/Audio_Registers.html#ff24--nr50-master-volume--vin-panning
	ld		a, $77
	ld		[rAUDVOL], a

	; Setup Channel 1.
	; Duty cycle of 50%, perfect square wave.
    ld      a, AUDLEN_DUTY_50
    ld      [rAUD1LEN], a

	; Channel envelope.
    ld      a, AUDENVF_INIT_VOL
    ld      [rAUD1ENV], a

	; Audio sweep.
	ld		a, $24
	ld		[rAUD1SWEEP], a

    ; Setup Channel 2.
    ; This works like Channel 1 but does not have a period sweep, this will be useful
    ; as a piano-like instrument.
    ; This is a square wave, we set it up now and then control it's frequency,
    ; thus making notes.
    ; Duty cycle of 50%, perfect square wave.
    ld      a, AUDLEN_DUTY_50
    ld      [rAUD2LEN], a

    ; Channel envelope.
    ld      a, AUDENVF_INIT_VOL
    ld      [rAUD2ENV], a

; Scroll the splash screen. This goes from above and moves down in place.
	call	ScrollSplashBG

; Wait until the player presses "start" button. This is input $08 in our
; input byte.
WaitForStart:
	call	ReadInput
	ld		a, [INPUT_BYTE_ADDR]
	cp		a, $08					; $08 is "start".
	jr		nz, WaitForStart

; This is the main game loop. This game is just a front for the actual challenge, which is unlocked
; by inputting the Konami code during the game. If the player takes too much time, a monster appears
; and causes the game to crash.
GameStarts:
	; Load the game background, we need to replace the splash scren from before.
	call	LoadGameBG
	; Load the monster at the top, but hidden from view. It'll move when the counter underflows.
	call	PrintDevil
	; Set up the counter for the monster to appear. We only need to set up the high byte since the low one always
	; starts at $00.
	ld		a, $01
	ld		[DEVIL_COUNTER_HIGH], a

; The game loop.

; We spawn a rock every 128 frames.
	ld		c, 128
.loop:
	dec		c
	; Skip rock spawn if 128 frames didn't passed already.
	jr		nz,.skipRockCreation

	; Spawn a rock at the Background.
	call	SpawnRock

	; Reload the spawn rock counter.
	ld		c, 128

.skipRockCreation:
	; These are all the routines that we need to call to make the game run.
	; These are called once per VBlank frame.

	; Update the rocks position.
	; FIXME: Maybe we can remove this routine.
	call	UpdateRocks

	; Read input from the player. Puts the result in INPUT_BYTE_ADDR and populates a buffer with it.
	call	ReadInput

	; FIXME: Should we hard jump or return here?
	; Check if the input buffer contains the Konami code. If so, hard jump to the admin panel. 
	call	CheckKonami

	; Move the player according to its input.
	call	CharacterAction

	; Scroll the background through the X axis.
	call	ScrollBG

	; Check for rock and player collision. Reset the game if the player lost.
	call	CheckCollision

	; DMA update to OAM, this is the recommended way to update the OAM.
	call	UpdateOAM

	; Decrement the monster counter low byte.
	ld		hl, DEVIL_COUNTER_LOW
	dec		[hl]
	; If we have not reached zero, keep running as usual.
	jr		nz,.keepCounting

	; We arrive here if the low byte in the monster counter underflowed.
	; That means we need to check if the high byte is also zero. If so, the devil appears.
	ld		a, [DEVIL_COUNTER_HIGH]
	or		a, [hl]
	jr		nz,.substractHighCounter

	; The high byte is also zero, that means the 2 byte counter underflowed. The devil will appear now.
	ld		a, 1
	ld		[DEVIL_ON_SCREEN], a
	jr		.keepCounting

.substractHighCounter:
	; Decrement the high byte and keep running the counter.
	ld		hl, DEVIL_COUNTER_HIGH
	dec		[hl]

.keepCounting:
	; If the byte that indicates the Devil is on screen is not zero, we need
	; to update the Devil's location. It'll slowly move towards the player and eventually
	; crash the game.
	ld		a, [DEVIL_ON_SCREEN]
	cp		a, 0
	jr		z,.skipDevil

	; Update the devil location.
	call	UpdateDevil

	; Check if the devil is near the player, if so crash the game.
	call	CheckCrash

.skipDevil:
	; Wait for a vertical blank, this makes sure we run the loop on every frame.
	call	WaitForVBlank

	; Loop back to the top.
	jr		.loop

; This is the "Admin panel", the flag is shown here after a Konami code is entered.
FlagLoop:
	; Erase the current background and display the flag input.
	call 	ShowTheFlag
.loop:
	; Read the input from the player.
	call	ReadInput

	; This is supposed to emulate what game engines do (like Godot). It runs a function every "physics" frame.
	; I ended up needing to do work through frames inside this routine, so the name stayed there but is no longer
	; doing work on one frame. Now it's working through frames. 
	call	FixedUpdate

	; Loop back to the top.
	jr		.loop

; #### Functions ####

; Reads the input from the register and writes all the inputs into INPUT_BYTE_ADDR.
ReadInput:
	PushAll

	; Obfuscate _IO into HL.
	ld		a, LOW(_IO)
	DecodeRegisterFF

	; First we need to read the input from the player. We can either get the directional buttons or the other buttons (A, B, Start, Select) at a time.
	; So first get the directional buttons (there's one bit for each one) and combine them with the other buttons (also 4 bits). The resulting byte
	; will have the information on the eight possible buttons that the player can press. This will be saved and later be used by many other functions.
	; Read the d-pad
	ld		a, JOYP_GET_DPAD	

	ld		[hl], a				; To get the input we must write the mask of the input we want to get.
	ld		a, [hl]			; Now the input is retrievable.

	; Store the result, invert it because it's lower active
	cpl							; Effectively 'not a'.
	and		a, JOYPF_INPUTS		; Mask the bits we want to use.
	; FIXME: Maybe we can use "swap" here to achieve the same result with less bytes?
	ShiftLeft4					; Move them to the high byte.
	; Store the result in "b" so we can still use "a".
	ld		b, a

	; Read the buttons
	ld		a, JOYP_GET_BTN
	ld		[hl], a			; Put the mask in order to retrieve the input we want.

	; Store the result, invert it because it's lower active
	ld		a, [hl]			; Read the input.
	cpl							; Effectively 'not a'.
	and		a, JOYPF_INPUTS		; Mask the bits we are interested in.
	or		a, b				; Add the stored bits from "b".

	; If there's input then we mark the INPUT_STORED_ADDR address and return.
	; We only store the input if the user releases the button.
	jr		nz,.setInputStored

	; We arrive here if there's no input.
	; We now check if there was a previous input, if so we need to push the buffer
	; with the new input from before.
	ld		a,[INPUT_BYTE_ADDR]
	cp		a, 0
	jr		z,.return

	; FIXME: We might remove this.
	; Calculate the value of the user's flag, with the expanded bits from BG.
	call	CalculateUserFlag

	; Now we have an input stored and the current input is 0, so we need to push the buffer
	; and store the new input byte. 
	call	PushInputDownTheBuffer
	call	PushFlagDownTheBuffer

	; Now clear the INPUT_BYTE and return.
	xor		a

.setInputStored:
	ld		[INPUT_BYTE_ADDR], a

.return:
	PopAll
	ret

; This function pushes inputs in INPUT_BUFFER_ADDR down for INPUT_BUFFER_LENGTH
PushInputDownTheBuffer:
	PushAll

	; Load a loop of INPUT_BUFFER_LENGTH
	; We need to copy the values from last to first
	ld		c, INPUT_BUFFER_LENGTH
	ld		hl, INPUT_BUFFER_ADDR + (INPUT_BUFFER_LENGTH - 1)
	ld		de, INPUT_BUFFER_ADDR + (INPUT_BUFFER_LENGTH - 1) - 1
.loop:
	ld		a, [de]
	ld		[hl-], a
	dec		de
	dec		c
	jr		nz,.loop

	ld		a, [INPUT_BYTE_ADDR]
	ld		[INPUT_BUFFER_ADDR], a

.return:
	PopAll
	ret

; I know a lot of this code is the same as the one above, but I don't have time to refactor it.
PushFlagDownTheBuffer:
	PushAll

	; Load a loop of INPUT_BUFFER_LENGTH
	; We need to copy the values from last to first
	ld		c, USER_FLAG_LENGTH
	ld		hl, USER_FLAG + (USER_FLAG_LENGTH - 1)
	ld		de, USER_FLAG + (USER_FLAG_LENGTH - 1) - 1
.loop:
	ld		a, [de]
	ld		[hl-], a
	dec		de
	dec		c
	jr		nz,.loop

	ld		a, [USER_FLAG_BYTE]
	ld		[USER_FLAG], a

	xor 	a
	ld		[USER_FLAG_BYTE], a

.return:
	PopAll
	ret

; Show the flag in the background.
ShowTheFlag:
	PushAll

	; Save the state of rLCDC to the stack.
	ld		a, [rLCDC]
	push	af
	; Disable the LCD so we can do VRAM operations.
	xor		a
	ld		[rLCDC], a

	; Remove the scrolling in X.
	ld		[rSCX], a

	; Clear the OAM.
	ld		hl, _OAMRAM
	xor		a
	ld		c, DevilOAMTilemap.end - CharacterOAMTilemap
.loop:
	ld		[hl+], a
	dec		c
	jr		nz,.loop

	; Copy the BG tilemap that has the flag.
	ld de, BackgroundTilemap
	ld hl, (_SCRN0 + 12*32)
	ld bc, BackgroundTilemap.end - BackgroundTilemap
	call 	CopyToVRAM

	; Restore rLCDC
	pop		af
	ld		[rLCDC], a

	PopAll
	ret

; This function takes the bytes from the flag and encrypts them with the
; user provided bytes.
EncryptFlag:
	PushAll

	; Copy the user flag to where it'll be encrypted.
	ld 		de, USER_FLAG
	ld 		hl, USER_ENCRYPTED_FLAG
	ld 		bc, 40
	call	CopyToRAM

	; Prepare for encryption. We'll use the key at KEY_LOCATION and encrypt the user bytes.
	; The result is stored in USER_ENCRYPTED_FLAG.
	; FIXME: Maybe we can remove this line?
	ld		hl, USER_ENCRYPTED_FLAG
	ld		de, KEY_LOCATION
	; We do 20 loops here because for each loop we encrypt 2 bytes, and there are 40 bytes to encrypt.
	; Start from 0 up until 40, because we'll need "c" to calculate the value of the correct key for each
	; pair of bytes.
	ld		c, 0
.loop:
	; Select the key for the pair of bytes that we'll encrypt. This will yield 4 bytes stored in [de] ... [de+3].
	call	EncryptBytes

	; Move two bytes.
	inc		hl
	inc		hl
	; Increase two so we pick the next bytes in the key. The key is 40 bytes long, so it moves the same way the input
	; bytes move.
	inc		c
	inc		c

	; Check if we reached 40, we need to move the byte to "a" for comparison.
	ld		a, c
	cp		a, 40
	jr		nz,.loop

.done:
	PopAll
	ret

; This function compares the value in USER_ENCRYPTED_FLAG with EncryptedFlag.
; Plays a "success" song if they match.
CompareFlag:
	PushAll

	; Load the user encrypted flag and the real encrypted flag.
	ld		hl, USER_ENCRYPTED_FLAG
	ld		de, EncryptedFlag
	ld		c, 40					; The flag is 40 bytes long.
.loop:
	ld		a, [de]
	ld		b, a
	ld		a, [hl+]
	cp		a, b
	jr		nz,.return				; If one bytes doesn't match, then we don't have the correct flag.
	
	; Byte matches, go to the next one. "hl" already incremented.
	inc		de
	dec		c
	jr		nz,.loop

	; The user found the flag! Play a success song.
	call	PrintDevil

	
.completeLoop:
	; Update the devil location.
	call	UpdateDevil

	; DMA update to OAM, this is the recommended way to update the OAM.
	call	UpdateOAM

	; Check if the devil is near the player, if so crash the game.
	call	CheckCrash

	call	WarningSound

	call	WaitForVBlank
	jr		.completeLoop

	; FIXME: Should we throw the devil here and crash the game?
.return:
	PopAll
	ret

WarningSound:
	push	af

	ld 		a, $d6
	ld 		[rAUD2LOW], a
	ld 		a, $86
	ld 		[rAUD2HIGH], a

	pop		af
	ret

; Plays a melody pointed by 'hl' with length 'bc'.
; It should be a struct like this:
; LowByte Pitch, HighByte Pitch, Delay in Frames
; Call it like this:
;   ld 		hl, Melody
; 	ld		bc, Melody.end - Melody
;	call	PlayMelody
PlayMelody:
	PushAll

.loop:
	ld 		a, [hl+]
	ld 		[rAUD2LOW], a
	ld 		a, [hl+]
	ld 		[rAUD2HIGH], a
	ld		a, [hl+]
	call	DelayNframes

	; "hl" already moved, so move "bc" instead.
	dec 	bc
	dec 	bc
	dec 	bc
	; Check if both "b" and "c" are zero.
	ld 		a, b
	or 		a, c
	jr 		nz,.loop

	PopAll
	ret

; Waits until N frames passed.
DelayNframes:
	push		af
.loop:
	call		WaitForVBlank
	dec			a
	jr			nz,.loop

	pop			af
	ret

; This was inteded to run every VBLANK, but I ended up needing more time to process stuff.
FixedUpdate:
	EXPORT FixedUpdate
	push	hl

	; This is a VBLANK counter so we encrypt only after a given amount of frames passed.
	; FIXME: Not sure if we need this anymore?
	ld 		hl, VBLANK_COUNTER_ADDR
	inc 	[hl]
	jr		nz,.return

	call	VBlankOverflow

.return:
	pop		hl
	ret

; This routine is called by FixedUpdate after a given number of frames passed. It encrypts the flag
; and checks if they match.
VBlankOverflow:
	PushAll

	; Encrypt the flag that the user put.
	call	EncryptFlag

	; Copy the 
	call	CopyDecryptedBytesToWindow
	
	; Compare the encrypted flag to the one stored in ROM, if they match then the user found the flag.
	call	CompareFlag

	; This whole counter thing...I don't like it. Think of something better.
	; BG Counter overflowed.
	ld		hl, BG_COUNTER_TRIGGER
	inc		[hl]
	jp		nz,.return

; Reload the trigger
	ld		a, BG_COUNTER_SPEED
	ld		[BG_COUNTER_TRIGGER], a

; Increase the BG counter, this is used for expanding the Input
; to 256.
	ld 		hl, BG_COUNTER_ADDR
	inc 	[hl]
	ld		a, [hl]

	FOR N, 7
		push	af
		ld		c, 2
		REPT N
			sla		c
		ENDR
		and		a, c
		REPT N + 1
			srl		a
		ENDR
		add		a, 77
		call	WaitForBlank
		ld		[_SCRN0+N+5*32+5], a
		pop		af
	ENDR

	cp		a, 128
	jr		nz,.return

; Reload the BG Counter.
	ld		a, 0
	ld		[BG_COUNTER_ADDR], a

.return:
	ld		a, VBLANK_COUNTER_START
	ld		[VBLANK_COUNTER_ADDR], a

	PopAll
	ret

; Expand the Input using BG_Counter
CalculateUserFlag:
	PushAll

	; Get the current counter and shift it to the left.
	ld		hl, BG_COUNTER_ADDR
	ld		c, [hl]
	sla		c

	ld		a, [INPUT_BYTE_ADDR]
	dec		a
	ld		b, [hl]
	and		a, b
	or		a, c

	ld		[USER_FLAG_BYTE], a

	PopAll
	ret

; Copy the Flag bytes into FLAG_BG_ADDR
CopyDecryptedBytesToWindow:
	PushAll

	ld		hl, FLAG_BG_ADDR
	ld		de, USER_FLAG
	ld		c,	40					; Flag length.
.loop:
	ld		a, [de]
	call	WaitForBlank

	ld		[hl+], a
	inc		de
	dec		c
	jr		nz,.loop

	PopAll
	ret

; Scroll the splash screen from above until the Y shift hits $00.
ScrollSplashBG:
	push	af

	; This is the value where the Background is not seen anymore.
	ld		a, $70
.loop
	ld		[rSCY], a
	call	WaitForVBlank
	call	WaitForVBlank
	dec		a
	jr		nz,.loop

	ld		[rSCY], a

	pop		af
	ret

; These is the starting position of the player.
def CHARACTER_START_X equ $10
def CHARACTER_START_Y equ $10

; Prints the game background, this is the part where the player actually plays the game.
LoadGameBG:
	PushAll

	; Save the state of rLCDC
	ld		a, [rLCDC]
	push	af

	; Turn the LCD off.
	xor		a
	ld		[rLCDC], a

	; Load the game's background.
	ld de, GameBackground
	ld hl, _SCRN0
	ld bc, GameBackground.end - GameBackground
	call 	CopyToRAM

	; Print the player on screen in OAM.
	call	PrintCharacter

	; Restore the rLCDC value.
	pop		af
	ld		[rLCDC], a

	PopAll
	ret

; Add a new rock to the floor.
; FIXME: There's a bug with spawning the second rock. I don't know...
SpawnRock:
	PushAll
	
	ld		a, [ROCK1]
	cp		a, 0
	jr		nz,.skipRock1

	; Spawn rock 1
	ld		hl, ROCK1_START
	ld		a, $e0
	ld		[ROCK1], a
	jr		.spawn

.skipRock1:
	ld		a, [ROCK2]
	cp		a, 0
	jr		nz,.skipRock2

	; Spawn rock 2
	ld		hl, ROCK2_START
	ld		a, $e0
	ld		[ROCK2], a

.spawn:
	ld		a, $B1				; Rock tile.
	call	WaitForBlank
	ld		[hl], a

.skipRock2:
.done:
	PopAll
	ret

; Check rocks and delete them if they are out of view.
UpdateRocks:
	PushAll

	ld		hl, ROCK1_START
	push	hl
	ld		hl, ROCK1
	push	hl
	ld		hl, ROCK2_START
	push	hl
	ld		hl, ROCK2
	push	hl

	ld		c, 2
.loop:
	pop		hl
	ld		a, [hl]
	cp		a, 0
	jr		nz,.decrement

	; Delete rock.
	pop		hl
	ld		a, $4f
	call	WaitForBlank
	ld		[hl], a
	jr		.continue

.decrement:
	dec		[hl]
	pop		hl
.continue:
	dec		c
	jr		nz,.loop

	PopAll
	ret

CharacterAction:
	PushAll

	; If the character is on the floor, then we're done.
	ld		a, [HEIGHT]
	cp		a, PLAYER_FLOOR
	jr		z,.checkInput

	; If we're here then the user is in the air, we need to move up or down.
.jumping:
	; Check if the movmenet is up or down.
	ld		a, [UP_OR_DOWN]
	cp		a, 0
	jr		nz,.up

.down:
	; Going down.
	ld		hl, HEIGHT
	inc		[hl]
	jr		.done

.up:
	; Going up until max. If we reach max height then stop and go down.
	ld		hl, HEIGHT
	ld		a, JUMP_MAX
	cp		a, [hl]
	jr		z,.reachedMax

	; Player is still going up, this means we need to decrease the 'y' value.
	dec		[hl]
	jr		.done

.reachedMax:
	; We're at the max altitude, so go down.
	; In coordinates it means to increase y.
	ld		a, 0
	ld		[UP_OR_DOWN], a
	ld		hl, HEIGHT
	inc		[hl]

.checkInput:
	; If the player didn't press the Jump button, end routine.
	ld		a, [INPUT_BYTE_ADDR]
	cp		a, $02
	jr		nz,.done

	; We arrive here if the player pressed the jump button, and is on the floor.
	; Set so that the player jumps in the next frame.
	ld		a, 1
	ld		[UP_OR_DOWN], a
	ld		hl, HEIGHT
	dec		[hl]

.done:
	call		UpdatePlayerYPosition
	PopAll
	ret

; Reads the height value and updates the player's tiles.
UpdatePlayerYPosition:
	ld		hl, OAM_IN_WRAM
	ld		c, CharacterOAMTilemap.end - CharacterOAMTilemap
	; Divide by 4.
	srl		c
	srl		c
.loop:
	ld		a, 2
	cp		a, c
	jr		nc,.lessThan2
	ld		a, 4
	cp		a, c
	jr		c,.moreThan4

	ld		a, [HEIGHT]
	sub		a, 8
	jr		.copyByte

.lessThan2:
	ld		a, [HEIGHT]
	sub		a, 16
	jr		.copyByte

.moreThan4:
	ld		a, [HEIGHT]
	jr		.copyByte

.copyByte:
	ld		[hl+], a
	inc		hl
	inc		hl
	inc		hl

	dec		c

	jr		nz,.loop
	ret

PrintCharacter:
	PushAll

	; Load the character.
	ld		hl, OAM_IN_WRAM
	ld		de, CharacterOAMTilemap
	ld		c, CharacterOAMTilemap.end - CharacterOAMTilemap
.loop:
	ld		a, [de]
	ld		[hl+], a
	inc		de
	dec		c
	jr		nz,.loop

	; Place the player on the floor.
	ld		a, PLAYER_FLOOR
	ld		[HEIGHT], a

	PopAll
	ret

; Scroll the background on X by 1.
ScrollBG:
	push	af

	ld		a, [rSCX]
	inc		a
	ld		[rSCX], a

	pop		af
	ret

; FIXME: Implement.
CheckCollision:
	ret

; Checks if the input array has the knoami code.
; If so, make a hard jump to the admin panel.
CheckKonami:
	PushAll

	ld		hl, KonamiCode
	ld		de, INPUT_BUFFER_ADDR
	ld		c, KonamiCode.end - KonamiCode
.loop:
	ld		a, [de]
	cp		a, [hl]
	jr		nz,.done
	
	inc		hl
	inc		de
	dec		c
	jr		nz,.loop

	PopAll
	; Pop one more for the 'ret' that we didn't use.
	pop		hl
	jp		FlagLoop

.done:
	PopAll
	ret

UpdateDevil:
	PushAll

	ld		hl, OAM_IN_WRAM + CharacterOAMTilemap.end - CharacterOAMTilemap
	ld		c, DevilOAMTilemap.end - DevilOAMTilemap
	srl		c
	srl		c
.loop:
	inc		[hl]
	inc		hl
	dec		[hl]
	inc		hl
	inc		hl
	inc		hl
	dec		c
	jr		nz,.loop

	PopAll
	ret

; Prints the Devil at the start.
PrintDevil:
	PushAll

	ld		hl, OAM_IN_WRAM + CharacterOAMTilemap.end - CharacterOAMTilemap
	ld		de, DevilOAMTilemap
	ld		c, DevilOAMTilemap.end - DevilOAMTilemap
.loop:
	ld		a, [de]
	ld		[hl+], a
	inc		de
	dec		c
	jr		nz,.loop

	PopAll
	ret

; This comes from https://gbdev.io/pandocs/OAM_DMA_Transfer.html#best-practices
; It does a DMA to OAM from a place in RAM we can choose.
UpdateOAM:
	push	af

    ld 	a, HIGH(OAM_IN_WRAM)
    ldh [rDMA], a  			; start DMA transfer (starts right after instruction)
    ld 	a, 40        		; delay for a total of 4×40 = 160 M-cycles
.wait
    dec a           		; 1 M-cycle
    jr nz, .wait    		; 3 M-cycles

	pop		af
	ret

; Check if we have to crash. We check if the devil is near the player, if so crash the game.
CheckCrash:
	push	af

	; The OAM we modify is in OAM_IN_WRAM, the devil is 16 bytes after that.
	ld		a, [OAM_IN_WRAM + CharacterOAMTilemap.end - CharacterOAMTilemap]
	cp		a, PLAYER_FLOOR
	jr		nz,.done

	; Hard jump to crash the game. Forget about maintaining the stack...
	jp		Crash

.done
	pop		af
	ret

; Crash the game, make it look cool. For this we write bytes to VRAM from a "random" source.
; Instead of generating a random source, just pick the instruction op codes from this ROM,
; they look good.
Crash:
	ld 		hl, _SCRN0
	ld		de, $00
	ld		bc, $02ff				; This amount of bytes is enough to break VRAM.
.loop:
	ld		a, [de]
	ld		[hl+], a
	inc		de
	dec		bc
	ld		a,b
	or		a,c
	jr		nz,.loop
	
	; Halt execution, this effectively stops PC from moving until an interrupt happens.
	; But we disabled interrupts, so it'll never come back up online.
	halt

; Play a Devil melody.
PlayDevilMelody:
	
	ret