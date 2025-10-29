; This file contains all the interesting locations of the challenge.

def FLAG_BG_ADDR equ _SCRN0 + 15*32 + 1

; This byte will hold the current input from the user.
def INPUT_BYTE_ADDR equ _RAM
; This is a buffer that'll store 40 previous inputs from the user.
def INPUT_BUFFER_ADDR equ INPUT_BYTE_ADDR + 1
def INPUT_BUFFER_LENGTH equ 40 ;$70

; Here we'll store the final encrypted flag, to be checked with the one stored in ROM.
def USER_ENCRYPTED_FLAG equ INPUT_BUFFER_ADDR + INPUT_BUFFER_LENGTH
def USER_ENCRYPTED_FLAG_LENGTH equ INPUT_BUFFER_LENGTH

; This is the user flag generated from the input and the expanded counter.
def USER_FLAG_BYTE equ USER_ENCRYPTED_FLAG + USER_ENCRYPTED_FLAG_LENGTH
def USER_FLAG equ USER_FLAG_BYTE + 1
def USER_FLAG_LENGTH equ INPUT_BUFFER_LENGTH

; This is the VBlank counter, this is used to wait N Vblanks but also
; allow other functions to continue.
def VBLANK_COUNTER_ADDR equ USER_FLAG + USER_FLAG_LENGTH
def VBLANK_COUNTER_START equ $e0

; This is the Background counter, this is used to expand the input to fill the 256 states.
def BG_COUNTER_ADDR equ VBLANK_COUNTER_ADDR + 1
; The trigger to increase the counter, so it increases slowly.
def BG_COUNTER_TRIGGER equ BG_COUNTER_ADDR + 1
def BG_COUNTER_SPEED equ $e0        ; More is faster.

def KEY_LOCATION equ BG_COUNTER_TRIGGER + 1
def KEY_LOCATION_LENGTH equ 4

def PLAYER_FLOOR equ 136
def JUMP_MAX equ 100
def HEIGHT equ KEY_LOCATION + KEY_LOCATION_LENGTH
def UP_OR_DOWN equ HEIGHT + 1

def ROCK1 equ UP_OR_DOWN + 1
def ROCK2 equ ROCK1 + 1
def ROCK1_START equ _SCRN0 + 490
def ROCK2_START equ _SCRN0 + 480

def DEVIL_COUNTER_HIGH equ ROCK2 + 1
def DEVIL_COUNTER_LOW equ DEVIL_COUNTER_HIGH + 1
def DEVIL_ON_SCREEN equ DEVIL_COUNTER_LOW + 1
def DEVIL_OAM equ _OAMRAM + 16

def OAM_IN_WRAM equ $D000
