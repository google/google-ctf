;******************************************************************************
; Game Boy hardware constant definitions
; https://github.com/gbdev/hardware.inc
;******************************************************************************

; To the extent possible under law, the authors of this work have
; waived all copyright and related or neighboring rights to the work.
; See https://creativecommons.org/publicdomain/zero/1.0/ for details.
; SPDX-License-Identifier: CC0-1.0

; If this file was already included, don't do it again
if !def(HARDWARE_INC)

; Check for the minimum supported RGBDS version
if !def(__RGBDS_MAJOR__) || !def(__RGBDS_MINOR__) || !def(__RGBDS_PATCH__)
    fail "This version of 'hardware.inc' requires RGBDS version 0.5.0 or later"
endc
if __RGBDS_MAJOR__ == 0 && __RGBDS_MINOR__ < 5
    fail "This version of 'hardware.inc' requires RGBDS version 0.5.0 or later."
endc

; Define the include guard and the current hardware.inc version
; (do this after the RGBDS version check since the `def` syntax depends on it)
def HARDWARE_INC equ 1
def HARDWARE_INC_VERSION equs "4.10.0"

; Usage: rev_Check_hardware_inc <min_ver>
; Examples:
;     rev_Check_hardware_inc 1.2.3
;     rev_Check_hardware_inc 1.2   (equivalent to 1.2.0)
;     rev_Check_hardware_inc 1     (equivalent to 1.0.0)
MACRO rev_Check_hardware_inc
    def hw_inc_cur_ver\@ equs strrpl("{HARDWARE_INC_VERSION}", ".", ",")
    def hw_inc_min_ver\@ equs strrpl("\1", ".", ",")
    def hw_inc_def_check\@ equs """MACRO hw_inc_check\@
        if \\1 != \\4 || (\\2 < \\5 || (\\2 == \\5 && \\3 < \\6))
            fail "Version \\1.\\2.\\3 of 'hardware.inc' is incompatible with requested version \\4.\\5.\\6"
        endc
    \nENDM"""
    hw_inc_def_check\@
    hw_inc_check\@ {hw_inc_cur_ver\@}, {hw_inc_min_ver\@}, 0, 0
    purge hw_inc_cur_ver\@, hw_inc_min_ver\@, hw_inc_def_check\@, hw_inc_check\@
ENDM


;******************************************************************************
; Memory-mapped registers ($FFxx range)
;******************************************************************************

; -- JOYP / P1 ($FF00) --------------------------------------------------------
; Joypad face buttons
def rJOYP equ $FF00

def JOYPB_GET_BTN  equ 5 ; 0 = reading buttons     [r/w]
def JOYPB_GET_DPAD equ 4 ; 0 = reading Control Pad [r/w]
    def JOYPF_GET equ %00_11_0000 ; select which inputs to read from the lower nybble
        def JOYP_GET_BTN  equ %00_01_0000 ; reading A/B/Select/Start buttons
        def JOYP_GET_DPAD equ %00_10_0000 ; reading Control Pad directions
        def JOYP_GET_NONE equ %00_11_0000 ; reading nothing

def JOYPB_START  equ 3 ; 0 = Start is pressed  (if reading buttons)     [ro]
def JOYPB_SELECT equ 2 ; 0 = Select is pressed (if reading buttons)     [ro]
def JOYPB_B      equ 1 ; 0 = B is pressed      (if reading buttons)     [ro]
def JOYPB_A      equ 0 ; 0 = A is pressed      (if reading buttons)     [ro]
def JOYPB_DOWN   equ 3 ; 0 = Down is pressed   (if reading Control Pad) [ro]
def JOYPB_UP     equ 2 ; 0 = Up is pressed     (if reading Control Pad) [ro]
def JOYPB_LEFT   equ 1 ; 0 = Left is pressed   (if reading Control Pad) [ro]
def JOYPB_RIGHT  equ 0 ; 0 = Right is pressed  (if reading Control Pad) [ro]
    def JOYPF_INPUTS equ %0000_1111
    def JOYPF_START  equ 1 << JOYPB_START
    def JOYPF_SELECT equ 1 << JOYPB_SELECT
    def JOYPF_B      equ 1 << JOYPB_B
    def JOYPF_A      equ 1 << JOYPB_A
    def JOYPF_DOWN   equ 1 << JOYPB_DOWN
    def JOYPF_UP     equ 1 << JOYPB_UP
    def JOYPF_LEFT   equ 1 << JOYPB_LEFT
    def JOYPF_RIGHT  equ 1 << JOYPB_RIGHT

; Combined input byte, with Control Pad in high nybble (conventional order)
def PADB_DOWN   equ 7
def PADB_UP     equ 6
def PADB_LEFT   equ 5
def PADB_RIGHT  equ 4
def PADB_START  equ 3
def PADB_SELECT equ 2
def PADB_B      equ 1
def PADB_A      equ 0
    def PADF_DOWN   equ 1 << PADB_DOWN
    def PADF_UP     equ 1 << PADB_UP
    def PADF_LEFT   equ 1 << PADB_LEFT
    def PADF_RIGHT  equ 1 << PADB_RIGHT
    def PADF_START  equ 1 << PADB_START
    def PADF_SELECT equ 1 << PADB_SELECT
    def PADF_B      equ 1 << PADB_B
    def PADF_A      equ 1 << PADB_A

; Combined input byte, with Control Pad in low nybble (swapped order)
def PADB_SWAP_START  equ 7
def PADB_SWAP_SELECT equ 6
def PADB_SWAP_B      equ 5
def PADB_SWAP_A      equ 4
def PADB_SWAP_DOWN   equ 3
def PADB_SWAP_UP     equ 2
def PADB_SWAP_LEFT   equ 1
def PADB_SWAP_RIGHT  equ 0
    def PADF_SWAP_START  equ 1 << PADB_SWAP_START
    def PADF_SWAP_SELECT equ 1 << PADB_SWAP_SELECT
    def PADF_SWAP_B      equ 1 << PADB_SWAP_B
    def PADF_SWAP_A      equ 1 << PADB_SWAP_A
    def PADF_SWAP_DOWN   equ 1 << PADB_SWAP_DOWN
    def PADF_SWAP_UP     equ 1 << PADB_SWAP_UP
    def PADF_SWAP_LEFT   equ 1 << PADB_SWAP_LEFT
    def PADF_SWAP_RIGHT  equ 1 << PADB_SWAP_RIGHT

; -- SB ($FF01) ---------------------------------------------------------------
; Serial transfer data [r/w]
def rSB equ $FF01

; -- SC ($FF02) ---------------------------------------------------------------
; Serial transfer control
def rSC equ $FF02

def SCB_START  equ 7 ; reading 1 = transfer in progress, writing 1 = start transfer        [r/w]
def SCB_SPEED  equ 1 ; (CGB only) 1 = use faster internal clock                            [r/w]
def SCB_SOURCE equ 0 ; 0 = use external clock ("slave"), 1 = use internal clock ("master") [r/w]
    def SCF_START  equ 1 << SCB_START
    def SCF_SPEED  equ 1 << SCB_SPEED
        def SC_SLOW equ 0 << SCB_SPEED
        def SC_FAST equ 1 << SCB_SPEED
    def SCF_SOURCE equ 1 << SCB_SOURCE
        def SC_EXTERNAL equ 0 << SCB_SOURCE
        def SC_INTERNAL equ 1 << SCB_SOURCE

; -- $FF03 is unused ----------------------------------------------------------

; -- DIV ($FF04) --------------------------------------------------------------
; Divider register [r/w]
def rDIV equ $FF04

; -- TIMA ($FF05) -------------------------------------------------------------
; Timer counter [r/w]
def rTIMA equ $FF05

; -- TMA ($FF06) --------------------------------------------------------------
; Timer modulo [r/w]
def rTMA equ $FF06

; -- TAC ($FF07) --------------------------------------------------------------
; Timer control
def rTAC equ $FF07

def TACB_START equ 2 ; enable incrementing TIMA [r/w]
    def TACF_STOP  equ 0 << TACB_START
    def TACF_START equ 1 << TACB_START

def TACF_CLOCK equ %000000_11 ; the frequency at which TIMER_CNT increments [r/w]
    def TACF_4KHZ   equ %000000_00 ; every 256 M-cycles = ~4 KHz on DMG
    def TACF_262KHZ equ %000000_01 ; every 4 M-cycles = ~262 KHz on DMG
    def TACF_65KHZ  equ %000000_10 ; every 16 M-cycles = ~65 KHz on DMG
    def TACF_16KHZ  equ %000000_11 ; every 64 M-cycles = ~16 KHz on DMG

; -- $FF08-$FF0E are unused ---------------------------------------------------

; -- IF ($FF0F) ---------------------------------------------------------------
; Pending interrupts
def rIF equ $FF0F

def IFB_JOYPAD equ 4 ; 1 = joypad interrupt is pending [r/w]
def IFB_SERIAL equ 3 ; 1 = serial interrupt is pending [r/w]
def IFB_TIMER  equ 2 ; 1 = timer  interrupt is pending [r/w]
def IFB_STAT   equ 1 ; 1 = STAT   interrupt is pending [r/w]
def IFB_VBLANK equ 0 ; 1 = VBlank interrupt is pending [r/w]
    def IFF_JOYPAD equ 1 << IFB_JOYPAD
    def IFF_SERIAL equ 1 << IFB_SERIAL
    def IFF_TIMER  equ 1 << IFB_TIMER
    def IFF_STAT   equ 1 << IFB_STAT
    def IFF_VBLANK equ 1 << IFB_VBLANK

; -- AUD1SWEEP / NR10 ($FF10) -------------------------------------------------
; Audio channel 1 sweep
def rAUD1SWEEP equ $FF10

def AUD1SWEEPF_TIME equ %0_111_0000 ; how long between sweep iterations
                                    ; (in 128 Hz ticks, ~7.8 ms apart) [r/w]

def AUD1SWEEPB_DIR equ 3 ; sweep direction [r/w]
    def AUD1SWEEPF_DIR equ 1 << AUD1SWEEPB_DIR
        def AUD1SWEEP_UP   equ 0 << AUD1SWEEPB_DIR
        def AUD1SWEEP_DOWN equ 1 << AUD1SWEEPB_DIR

def AUD1SWEEP_SHIFT equ %00000_111 ; how much the period increases/decreases per iteration [r/w]

; -- AUD1LEN / NR11 ($FF11) ---------------------------------------------------
; Audio channel 1 length timer and duty cycle
def rAUD1LEN equ $FF11

; These values are also applicable to AUD2LEN
def AUDLENF_DUTY equ %11_000000 ; ratio of time spent high vs. time spent low [r/w]
    def AUDLEN_DUTY_12_5 equ %00_000000 ; 12.5%
    def AUDLEN_DUTY_25   equ %01_000000 ; 25%
    def AUDLEN_DUTY_50   equ %10_000000 ; 50%
    def AUDLEN_DUTY_75   equ %11_000000 ; 75%

; This value is also applicable to AUD2LEN and AUD4LEN
def AUDLENF_TIMER equ %00_111111 ; initial length timer (0-63) [wo]

; -- AUD1ENV / NR12 ($FF12) ---------------------------------------------------
; Audio channel 1 volume and envelope
def rAUD1ENV equ $FF12

; Values are also applicable to AUD2ENV and AUD4ENV

def AUDENVF_INIT_VOL equ %1111_0000 ; initial volume [r/w]

def AUDENVB_DIR equ 3 ; direction of volume envelope [r/w]
    def AUDENVF_DIR equ 1 << AUDENVB_DIR
        def AUDENV_DOWN equ 0 << AUDENVB_DIR
        def AUDENV_UP   equ 1 << AUDENVB_DIR

def AUDENVF_PACE equ %00000_111 ; how long between envelope iterations
                                ; (in 64 Hz ticks, ~15.6 ms apart) [r/w]

; -- AUD1LOW / NR13 ($FF13) ---------------------------------------------------
; Audio channel 1 period (low 8 bits) [r/w]
def rAUD1LOW equ $FF13

; -- AUD1HIGH / NR14 ($FF14) --------------------------------------------------
; Audio channel 1 period (high 3 bits) and control
def rAUD1HIGH equ $FF14

; Values are also applicable to AUD2HIGH and AUD3HIGH

def AUDHIGHB_RESTART    equ 7 ; 1 = restart the channel [wo]
def AUDHIGHB_LEN_ENABLE equ 6 ; 1 = reset the channel after the length timer expires [r/w]
    def AUDHIGH_RESTART    equ 1 << AUDHIGHB_RESTART
    def AUDHIGH_LENGTH_OFF equ 0 << AUDHIGHB_LEN_ENABLE
    def AUDHIGH_LENGTH_ON  equ 1 << AUDHIGHB_LEN_ENABLE

def AUDHIGHF_PERIOD_HIGH equ %00000_111 ; upper 3 bits of the channel's period [r/w]

; -- $FF15 is unused ----------------------------------------------------------

; -- AUD2LEN / NR21 ($FF16) ---------------------------------------------------
; Audio channel 2 length timer and duty cycle
def rAUD2LEN equ $FF16

; Values are reused from AUD1LEN

; -- AUD2ENV / NR22 ($FF17) ---------------------------------------------------
; Audio channel 2 volume and envelope
def rAUD2ENV equ $FF17

; Values are reused from AUD1ENV

; -- AUD2LOW / NR23 ($FF18) ---------------------------------------------------
; Audio channel 2 period (low 8 bits) [r/w]
def rAUD2LOW equ $FF18

; -- AUD2HIGH / NR24 ($FF19) --------------------------------------------------
; Audio channel 2 period (high 3 bits) and control
def rAUD2HIGH equ $FF19

; Values are reused from AUD1HIGH

; -- AUD3ENA / NR30 ($FF1A) ---------------------------------------------------
; Audio channel 3 enable
def rAUD3ENA equ $FF1A

def AUD3ENAB_ENABLE equ 7 ; 1 = channel is active [r/w]
    def AUD3ENA_OFF equ 0 << AUD3ENAB_ENABLE
    def AUD3ENA_ON  equ 1 << AUD3ENAB_ENABLE

; -- AUD3LEN / NR31 ($FF1B) ---------------------------------------------------
; Audio channel 3 length timer [wo]
def rAUD3LEN equ $FF1B

; -- AUD3LEVEL / NR32 ($FF1C) -------------------------------------------------
; Audio channel 3 volume
def rAUD3LEVEL equ $FF1C

def AUD3LEVELF_VOLUME equ %0_11_00000 ; volume level [r/w]
    def AUD3LEVEL_MUTE equ %0_00_00000 ; 0% (muted)
    def AUD3LEVEL_100  equ %0_01_00000 ; 100%
    def AUD3LEVEL_50   equ %0_10_00000 ; 50%
    def AUD3LEVEL_25   equ %0_11_00000 ; 25%

; -- AUD3LOW / NR33 ($FF1D) ---------------------------------------------------
; Audio channel 3 period (low 8 bits) [r/w]
def rAUD3LOW equ $FF1D

; -- AUD3HIGH / NR34 ($FF1E) --------------------------------------------------
; Audio channel 3 period (high 3 bits) and control
def rAUD3HIGH equ $FF1E

; Values are reused from AUD1HIGH

; -- $FF1F is unused ----------------------------------------------------------

; -- AUD4LEN / NR41 ($FF20) ---------------------------------------------------
; Audio channel 4 length timer [wo]
def rAUD4LEN equ $FF20

; AUDLENF_TIMER value is reused from AUD1LEN

; -- AUD4ENV / NR42 ($FF21) ---------------------------------------------------
; Audio channel 4 volume and envelope
def rAUD4ENV equ $FF21

; Values are reused from AUD1ENV

; -- AUD4POLY / NR43 ($FF22) --------------------------------------------------
; Audio channel 4 period and randomness
def rAUD4POLY equ $FF22

def AUD4POLYF_SHIFT equ %1111_0000 ; coarse control of the channel's period [r/w]

def AUD4POLYB_WIDTH equ 3 ; controls the noise generator (LFSR)'s step width [r/w]
    def AUD4POLY_15STEP equ 0 << AUD4POLYB_WIDTH
    def AUD4POLY_7STEP  equ 1 << AUD4POLYB_WIDTH

def AUD4POLYF_DIV equ %00000_111 ; fine control of the channel's period [r/w]

; -- AUD4GO / NR44 ($FF23) ----------------------------------------------------
; Audio channel 4 control
def rAUD4GO equ $FF23

def AUD4GOB_RESTART    equ 7 ; 1 = restart the channel [wo]
def AUD4GOB_LEN_ENABLE equ 6 ; 1 = reset the channel after the length timer expires [r/w]
    def AUD4GO_RESTART    equ 1 << AUD4GOB_RESTART
    def AUD4GO_LENGTH_OFF equ 0 << AUD4GOB_LEN_ENABLE
    def AUD4GO_LENGTH_ON  equ 1 << AUD4GOB_LEN_ENABLE

; -- AUDVOL / NR50 ($FF24) ----------------------------------------------------
; Audio master volume and VIN mixer
def rAUDVOL equ $FF24

def AUDVOLB_VIN_LEFT  equ 7 ; 1 = output VIN to left ear (SO2, speaker 2) [r/w]
    def AUDVOL_VIN_LEFT equ 1 << AUDVOLB_VIN_LEFT

def AUDVOLF_LEFT equ %0_111_0000 ; 0 = barely audible, 7 = full volume [r/w]

def AUDVOLB_VIN_RIGHT equ 3 ; 1 = output VIN to right ear (SO1, speaker 1) [r/w]
    def AUDVOL_VIN_RIGHT equ 1 << AUDVOLB_VIN_RIGHT

def AUDVOLF_RIGHT equ %00000_111 ; 0 = barely audible, 7 = full volume [r/w]

; -- AUDTERM / NR51 ($FF25) ---------------------------------------------------
; Audio channel mixer
def rAUDTERM equ $FF25

def AUDTERMB_4_LEFT  equ 7 ; 1 = output channel 4 to left  ear [r/w]
def AUDTERMB_3_LEFT  equ 6 ; 1 = output channel 3 to left  ear [r/w]
def AUDTERMB_2_LEFT  equ 5 ; 1 = output channel 2 to left  ear [r/w]
def AUDTERMB_1_LEFT  equ 4 ; 1 = output channel 1 to left  ear [r/w]
def AUDTERMB_4_RIGHT equ 3 ; 1 = output channel 4 to right ear [r/w]
def AUDTERMB_3_RIGHT equ 2 ; 1 = output channel 3 to right ear [r/w]
def AUDTERMB_2_RIGHT equ 1 ; 1 = output channel 2 to right ear [r/w]
def AUDTERMB_1_RIGHT equ 0 ; 1 = output channel 1 to right ear [r/w]
    def AUDTERM_4_LEFT  equ 1 << AUDTERMB_4_LEFT
    def AUDTERM_3_LEFT  equ 1 << AUDTERMB_3_LEFT
    def AUDTERM_2_LEFT  equ 1 << AUDTERMB_2_LEFT
    def AUDTERM_1_LEFT  equ 1 << AUDTERMB_1_LEFT
    def AUDTERM_4_RIGHT equ 1 << AUDTERMB_4_RIGHT
    def AUDTERM_3_RIGHT equ 1 << AUDTERMB_3_RIGHT
    def AUDTERM_2_RIGHT equ 1 << AUDTERMB_2_RIGHT
    def AUDTERM_1_RIGHT equ 1 << AUDTERMB_1_RIGHT

; -- AUDENA / NR52 ($FF26) ----------------------------------------------------
; Audio master enable
def rAUDENA equ $FF26

def AUDENAB_ENABLE     equ 7 ; 0 = disable the APU (resets all audio registers to 0!) [r/w]
def AUDENAB_ENABLE_CH4 equ 3 ; 1 = channel 4 is running [ro]
def AUDENAB_ENABLE_CH3 equ 2 ; 1 = channel 3 is running [ro]
def AUDENAB_ENABLE_CH2 equ 1 ; 1 = channel 2 is running [ro]
def AUDENAB_ENABLE_CH1 equ 0 ; 1 = channel 1 is running [ro]
    def AUDENA_OFF      equ 0 << AUDENAB_ENABLE
    def AUDENA_ON       equ 1 << AUDENAB_ENABLE
    def AUDENAF_CH4_OFF equ 0 << AUDENAB_ENABLE_CH4
    def AUDENAF_CH4_ON  equ 1 << AUDENAB_ENABLE_CH4
    def AUDENAF_CH3_OFF equ 0 << AUDENAB_ENABLE_CH3
    def AUDENAF_CH3_ON  equ 1 << AUDENAB_ENABLE_CH3
    def AUDENAF_CH2_OFF equ 0 << AUDENAB_ENABLE_CH2
    def AUDENAF_CH2_ON  equ 1 << AUDENAB_ENABLE_CH2
    def AUDENAF_CH1_OFF equ 0 << AUDENAB_ENABLE_CH1
    def AUDENAF_CH1_ON  equ 1 << AUDENAB_ENABLE_CH1

; -- $FF27-$FF2F are unused ---------------------------------------------------

; -- AUD3WAVE ($FF30-$FF3F) ---------------------------------------------------
; Audio channel 3 wave pattern RAM [r/w]
def _AUD3WAVERAM equ $FF30 ; $FF30-$FF3F

def rAUD3WAVE_0 equ $FF30
def rAUD3WAVE_1 equ $FF31
def rAUD3WAVE_2 equ $FF32
def rAUD3WAVE_3 equ $FF33
def rAUD3WAVE_4 equ $FF34
def rAUD3WAVE_5 equ $FF35
def rAUD3WAVE_6 equ $FF36
def rAUD3WAVE_7 equ $FF37
def rAUD3WAVE_8 equ $FF38
def rAUD3WAVE_9 equ $FF39
def rAUD3WAVE_A equ $FF3A
def rAUD3WAVE_B equ $FF3B
def rAUD3WAVE_C equ $FF3C
def rAUD3WAVE_D equ $FF3D
def rAUD3WAVE_E equ $FF3E
def rAUD3WAVE_F equ $FF3F

def AUD3WAVE_SIZE equ 16

; -- LCDC ($FF40) -------------------------------------------------------------
; PPU graphics control
def rLCDC equ $FF40

def LCDCB_ON      equ 7 ; whether the PPU (and LCD) are turned on          [r/w]
def LCDCB_WIN9C00 equ 6 ; which tilemap the Window reads from              [r/w]
def LCDCB_WINON   equ 5 ; whether the Window is enabled                    [r/w]
def LCDCB_BLKS    equ 4 ; which "tile blocks" the BG and Window use        [r/w]
def LCDCB_BG9C00  equ 3 ; which tilemap the BG reads from                  [r/w]
def LCDCB_OBJ16   equ 2 ; how many pixels tall each OBJ is                 [r/w]
def LCDCB_OBJON   equ 1 ; whether OBJs are enabled                         [r/w]
def LCDCB_BGON    equ 0 ; (DMG only) whether the BG is enabled             [r/w]
def LCDCB_PRION   equ 0 ; (CGB only) whether OBJ priority bits are enabled [r/w]
    def LCDCF_OFF     equ 0 << LCDCB_ON
    def LCDCF_ON      equ 1 << LCDCB_ON
    def LCDCF_WIN9800 equ 0 << LCDCB_WIN9C00
    def LCDCF_WIN9C00 equ 1 << LCDCB_WIN9C00
    def LCDCF_WINOFF  equ 0 << LCDCB_WINON
    def LCDCF_WINON   equ 1 << LCDCB_WINON
    def LCDCF_BLKS    equ 1 << LCDCB_BLKS
    def LCDCF_BLK21   equ 0 << LCDCB_BLKS
    def LCDCF_BLK01   equ 1 << LCDCB_BLKS
    def LCDCF_BG9800  equ 0 << LCDCB_BG9C00
    def LCDCF_BG9C00  equ 1 << LCDCB_BG9C00
    def LCDCF_OBJ8    equ 0 << LCDCB_OBJ16
    def LCDCF_OBJ16   equ 1 << LCDCB_OBJ16
    def LCDCF_OBJOFF  equ 0 << LCDCB_OBJON
    def LCDCF_OBJON   equ 1 << LCDCB_OBJON
    def LCDCF_BGOFF   equ 0 << LCDCB_BGON
    def LCDCF_BGON    equ 1 << LCDCB_BGON
    def LCDCF_PRIOFF  equ 0 << LCDCB_PRION
    def LCDCF_PRION   equ 1 << LCDCB_PRION

; -- STAT ($FF41) -------------------------------------------------------------
; Graphics status and interrupt control
def rSTAT equ $FF41

def STATB_LYC    equ 6 ; 1 = LY match triggers the STAT interrupt [r/w]
def STATB_MODE10 equ 5 ; 1 = OAM Scan triggers the PPU interrupt  [r/w]
def STATB_MODE01 equ 4 ; 1 = VBlank triggers the PPU interrupt    [r/w]
def STATB_MODE00 equ 3 ; 1 = HBlank triggers the PPU interrupt    [r/w]
def STATB_LYCF   equ 2 ; 1 = LY is currently equal to LYC         [ro]
def STATB_BUSY   equ 1 ; 1 = the PPU is currently accessing VRAM  [ro]
    def STATF_LYC    equ 1 << STATB_LYC
    def STATF_MODE10 equ 1 << STATB_MODE10
    def STATF_MODE01 equ 1 << STATB_MODE01
    def STATF_MODE00 equ 1 << STATB_MODE00
    def STATF_LYCF   equ 1 << STATB_LYCF
    def STATF_BUSY   equ 1 << STATB_BUSY

def STATF_MODE equ %000000_11 ; PPU's current status [ro]
    def STATF_HBL equ %000000_00 ; waiting after a line's rendering (HBlank)
    def STATF_VBL equ %000000_01 ; waiting between frames (VBlank)
    def STATF_OAM equ %000000_10 ; checking which OBJs will be rendered on this line (OAM scan)
    def STATF_LCD equ %000000_11 ; pushing pixels to the LCD

; -- SCY ($FF42) --------------------------------------------------------------
; Background Y scroll offset (in pixels) [r/w]
def rSCY equ $FF42

; -- SCX ($FF43) --------------------------------------------------------------
; Background X scroll offset (in pixels) [r/w]
def rSCX equ $FF43

; -- LY ($FF44) ---------------------------------------------------------------
; Y coordinate of the line currently processed by the PPU (0-153) [ro]
def rLY equ $FF44

def LY_VBLANK equ 144 ; 144-153 is the VBlank period

; -- LYC ($FF45) --------------------------------------------------------------
; Value that LY is constantly compared to [r/w]
def rLYC equ $FF45

; -- DMA ($FF46) --------------------------------------------------------------
; OAM DMA start address (high 8 bits) and start [wo]
def rDMA equ $FF46

; -- BGP ($FF47) --------------------------------------------------------------
; (DMG only) Background color mapping [r/w]
def rBGP equ $FF47

def BGP_SGB_TRANSFER equ %11_10_01_00 ; set BGP to this value before SGB VRAM transfer

; -- OBP0 ($FF48) -------------------------------------------------------------
; (DMG only) OBJ color mapping #0 [r/w]
def rOBP0 equ $FF48

; -- OBP1 ($FF49) -------------------------------------------------------------
; (DMG only) OBJ color mapping #1 [r/w]
def rOBP1 equ $FF49

; -- WY ($FF4A) ---------------------------------------------------------------
; Y coordinate of the Window's top-left pixel (0-143) [r/w]
def rWY equ $FF4A

; -- WX ($FF4B) ---------------------------------------------------------------
; X coordinate of the Window's top-left pixel, plus 7 (7-166) [r/w]
def rWX equ $FF4B

def WX_OFS equ 7 ; subtract this to get the actual Window Y coordinate

; -- KEY0 ($FF4C) -------------------------------------------------------------
; (CGB boot ROM only) CPU mode select
def rKEY0 equ $FF4C

; KEY0 is known as the "CPU mode register" in Fig. 11 of this patent:
; https://patents.google.com/patent/US6322447B1/en?oq=US6322447bi
; "OBJ priority mode designating register" in the same patent
; Credit to @mattcurrie for this finding!

def KEY0F_MODE equ %0000_11_00 ; current system mode [r/w]
    def KEY0F_CGB  equ %0000_00_00 ; CGB mode
    def KEY0F_DMG  equ %0000_01_00 ; DMG compatibility mode
    def KEY0F_PGB1 equ %0000_10_00 ; LCD is driven externally, CPU is stopped
    def KEY0F_PGB2 equ %0000_11_00 ; LCD is driven externally, CPU is running

; -- SPD / KEY1 ($FF4D) -------------------------------------------------------
; (CGB only) Double-speed mode control
def rSPD equ $FF4D

def SPDB_DBLSPEED equ 7 ; current clock speed                                  [ro]
def SPDB_PREPARE  equ 0 ; 1 = next `stop` instruction will switch clock speeds [r/w]
    def SPDF_DBLSPEED equ 1 << SPDB_DBLSPEED
    def SPDF_PREPARE  equ 1 << SPDB_PREPARE

; -- $FF4E is unused ----------------------------------------------------------

; -- VBK ($FF4F) --------------------------------------------------------------
; (CGB only) VRAM bank number (0 or 1)
def rVBK equ $FF4F

def VBK_BANK equ %0000000_1 ; mapped VRAM bank [r/w]

; -- BANK ($FF50) -------------------------------------------------------------
; (boot ROM only) Boot ROM mapping control
def rBANK equ $FF50

def BANKB_ON equ 0 ; whether the boot ROM is mapped [wo]
    def BANKF_ON  equ 0 << BANKB_ON
    def BANKF_OFF equ 1 << BANKB_ON

; -- VDMA_SRC_HIGH / HDMA1 ($FF51) --------------------------------------------
; (CGB only) VRAM DMA source address (high 8 bits) [wo]
def rVDMA_SRC_HIGH equ $FF51

; -- VDMA_SRC_LO / HDMA2 ($FF52) ----------------------------------------------
; (CGB only) VRAM DMA source address (low 8 bits) [wo]
def rVDMA_SRC_LOW equ $FF52

; -- VDMA_DEST_HIGH / HDMA3 ($FF53) -------------------------------------------
; (CGB only) VRAM DMA destination address (high 8 bits) [wo]
def rVDMA_DEST_HIGH equ $FF53

; -- VDMA_DEST_LOW / HDMA3 ($FF54) --------------------------------------------
; (CGB only) VRAM DMA destination address (low 8 bits) [wo]
def rVDMA_DEST_LOW equ $FF54

; -- VDMA_LEN / HDMA5 ($FF55) -------------------------------------------------
; (CGB only) VRAM DMA length, mode, and start
def rVDMA_LEN equ $FF55

def VDMA_LENB_MODE equ 7 ; on write: VRAM DMA mode [wo]
    def VDMA_LENF_MODE equ 1 << VDMA_LENB_MODE
        def VDMA_LENF_MODE_GP  equ 0 << VDMA_LENB_MODE ; GDMA (general-purpose)
        def VDMA_LENF_MODE_HBL equ 1 << VDMA_LENB_MODE ; HDMA (HBlank)

def VDMA_LENB_BUSY equ 7 ; on read: is a VRAM DMA active?
    def VDMA_LENF_BUSY equ 1 << VDMA_LENB_BUSY
        def VDMA_LENF_NO  equ 0 << VDMA_LENB_BUSY
        def VDMA_LENF_YES equ 1 << VDMA_LENB_BUSY

def VDMA_LENB_SIZE equ %0_1111111 ; how many 16-byte blocks (minus 1) to transfer [r/w]

; -- RP ($FF56) ---------------------------------------------------------------
; (CGB only) Infrared communications port
def rRP equ $FF56

def RPF_READ equ %11_000000 ; whether the IR read is enabled [r/w]
    def RPF_DISREAD equ %00_000000
    def RPF_ENREAD  equ %11_000000

def RPB_DATAIN equ 1 ; 0 = IR light is being received [ro]
def RPB_LED_ON equ 0 ; 1 = IR light is being sent     [r/w]
    def RPF_DATAIN   equ 1 << RPB_DATAIN
    def RPF_LED_ON equ 1 << RPB_LED_ON
        def RPF_WRITE_LO equ 0 << RPB_LED_ON
        def RPF_WRITE_HI equ 1 << RPB_LED_ON

; -- $FF57-$FF67 are unused ---------------------------------------------------

; -- BGPI / BCPS ($FF68) ------------------------------------------------------
; (CGB only) Background palette I/O index
def rBGPI equ $FF68

def BGPIB_AUTOINC equ 7 ; whether the index field is incremented after each write to BCPD [r/w]
    def BGPIF_AUTOINC equ 1 << BGPIB_AUTOINC

def BGPIF_INDEX equ %00_111111 ; the index within Palette RAM accessed via BCPD [r/w]

; -- BGPD / BCPD ($FF69) ------------------------------------------------------
; (CGB only) Background palette I/O access [r/w]
def rBGPD equ $FF69

; -- OBPI / OCPS ($FF6A) ------------------------------------------------------
; (CGB only) OBJ palette I/O index
def rOBPI equ $FF6A

def OBPIB_AUTOINC equ 7 ; whether the index field is incremented after each write to OBPD [r/w]
    def OBPIF_AUTOINC equ 1 << OBPIB_AUTOINC

def OBPIF_INDEX equ %00_111111 ; the index within Palette RAM accessed via OBPD [r/w]

; -- OBPD / OCPD ($FF6B) ------------------------------------------------------
; (CGB only) OBJ palette I/O access [r/w]
def rOBPD equ $FF6B

; -- OPRI ($FF6C) -------------------------------------------------------------
; (CGB boot ROM only) OBJ draw priority mode
def rOPRI equ $FF6C

def OPRIB_PRI equ 0 ; which drawing priority is used for OBJs [r/w]
    def OPRIF_PRI equ 1 << OPRIB_PRI
        def OPRI_OAM   equ 0 << OPRIB_PRI ; CGB mode default: earliest OBJ in OAM wins
        def OPRI_COORD equ 1 << OPRIB_PRI ; DMG mode default: leftmost OBJ wins

; -- $FF6D-$FF6F are unused ---------------------------------------------------

; -- WBK / SVBK / SMBK ($FF70) ------------------------------------------------
; (CGB only) WRAM bank number
def rWBK equ $FF70

def WBKF_BANK equ %00000_111 ; mapped WRAM bank (0-7) [r/w]

; -- $FF71-$FF75 are unused ---------------------------------------------------

; -- PCM12 ($FF76) ------------------------------------------------------------
; Audio channels 1 and 2 output
def rPCM12 equ $FF76

def PCM12F_CH2 equ %1111_0000 ; audio channel 2 output [ro]
def PCM12F_CH1 equ %0000_1111 ; audio channel 1 output [ro]

; -- PCM34 ($FF77) ------------------------------------------------------------
; Audio channels 3 and 4 output
def rPCM34 equ $FF77

def PCM34F_CH4 equ %1111_0000 ; audio channel 4 output [ro]
def PCM34F_CH3 equ %0000_1111 ; audio channel 3 output [ro]

; -- $FF78-$FF7F are unused ---------------------------------------------------

; -- IE ($FFFF) ---------------------------------------------------------------
; Interrupt enable
def rIE equ $FFFF

def IEB_JOYPAD equ 4 ; 1 = joypad interrupt is enabled [r/w]
def IEB_SERIAL equ 3 ; 1 = serial interrupt is enabled [r/w]
def IEB_TIMER  equ 2 ; 1 = timer  interrupt is enabled [r/w]
def IEB_STAT   equ 1 ; 1 = STAT   interrupt is enabled [r/w]
def IEB_VBLANK equ 0 ; 1 = VBlank interrupt is enabled [r/w]
    def IEF_JOYPAD equ 1 << IEB_JOYPAD
    def IEF_SERIAL equ 1 << IEB_SERIAL
    def IEF_TIMER  equ 1 << IEB_TIMER
    def IEF_STAT   equ 1 << IEB_STAT
    def IEF_VBLANK equ 1 << IEB_VBLANK


;******************************************************************************
; Cartridge registers (MBC)
;******************************************************************************

; Note that these "registers" are each actually accessible at an entire address range;
; however, one address for each of these ranges is considered the "canonical" one, and
; these addresses are what's provided here.

; -- RAMG ($0000-$1FFF) -------------------------------------------------------
; Whether SRAM can be accessed [wo]
def rRAMG equ $0000

; Common values
def CART_SRAM_DISABLE equ $00
def CART_SRAM_ENABLE  equ $0A ; some MBCs accept any value whose low nybble is $A

; -- ROMB0 ($2000-$3FFF) ------------------------------------------------------
; ROM bank number (low 8 bits when applicable) [wo]
def rROMB0 equ $2000

; -- ROMB1 ($3000-$3FFF) ------------------------------------------------------
; (MBC5 only) ROM bank number high bit (bit 8) [wo]
def rROMB1 equ $3000

; -- RAMB ($4000-$5FFF) -------------------------------------------------------
    ; SRAM bank number [wo]
def rRAMB equ $4000

; (MBC3-only) Special RAM bank numbers that actually map values into RTCREG
def RTC_S  equ $08 ; seconds counter (0-59)
def RTC_M  equ $09 ; minutes counter (0-59)
def RTC_H  equ $0A ; hours counter (0-23)
def RTC_DL equ $0B ; days counter, low byte (0-255)
def RTC_DH equ $0C ; days counter, high bit and other flags
    def RTC_DHB_CARRY equ 7 ; 1 = days counter overflowed    [wo]
    def RTC_DHB_HALT  equ 6 ; 0 = run timer, 1 = stop timer  [wo]
    def RTC_DHB_HIGH  equ 0 ; days counter, high bit (bit 8) [wo]
        def RTC_DHF_CARRY equ 1 << RTC_DHB_CARRY
        def RTC_DHF_HALT  equ 1 << RTC_DHB_HALT
        def RTC_DHF_HIGH  equ 1 << RTC_DHB_HIGH

def CARTB_RUMBLE_ON equ 3 ; (MBC5 and MBC7 only) enable the rumble motor (if any)
    def CARTF_RUMBLE_ON equ 1 << CARTB_RUMBLE_ON
        def CART_RUMBLE_OFF equ 0 << CARTB_RUMBLE_ON
        def CART_RUMBLE_ON  equ 1 << CARTB_RUMBLE_ON

; -- RTCLATCH ($6000-$7FFF) ---------------------------------------------------
; (MBC3 only) RTC latch clock data [wo]
def rRTCLATCH equ $6000

; Write $00 then $01 to latch the current time into RTCREG
def RTCLATCH_START  equ $00
def RTCLATCH_FINISH equ $01

; -- RTCREG ($A000-$BFFF) ---------------------------------------------------
; (MBC3 only) RTC register [r/w]
def rRTCREG equ $A000


;******************************************************************************
; Screen-related constants
;******************************************************************************

def SCRN_X   equ 160 ; width of screen in pixels
def SCRN_Y   equ 144 ; height of screen in pixels
def SCRN_X_B equ  20 ; width of screen in bytes
def SCRN_Y_B equ  18 ; height of screen in bytes

def SCRN_VX   equ 256 ; width of tilemap in pixels
def SCRN_VY   equ 256 ; height of tilemap in pixels
def SCRN_VX_B equ  32 ; width of tilemap in bytes
def SCRN_VY_B equ  32 ; height of tilemap in bytes

def TILE_X equ  8 ; width of tile in pixels
def TILE_Y equ  8 ; height of tile in pixels
def TILE_B equ 16 ; size of tile in bytes (2 bits/pixel)

def COLOR_B    equ 2 ; size of color in bytes (little-endian BGR555)
    def COLORF_GREEN_LOW  equ %111_00000  ; for the low byte
    def COLORF_RED        equ %000_11111  ; for the low byte
    def COLORF_BLUE       equ %0_11111_00 ; for the high byte
    def COLORF_GREEN_HIGH equ %000000_11  ; for the high byte
def PAL_COLORS equ 4 ; colors per palette
def PAL_B      equ COLOR_B * PAL_COLORS ; size of palette in bytes

; Tilemaps the BG or Window can read from (controlled by LCDC)
def _SCRN0 equ $9800 ; $9800-$9BFF
def _SCRN1 equ $9C00 ; $9C00-$9FFF


;******************************************************************************
; OBJ-related constants
;******************************************************************************

; OAM attribute field offsets
rsreset
def OAMA_Y      rb ; 0
    def OAM_Y_OFS equ 16 ; subtract 16 from what's written to OAM to get the real Y position
def OAMA_X      rb ; 1
    def OAM_X_OFS equ  8 ; subtract 8 from what's written to OAM to get the real X position
def OAMA_TILEID rb ; 2
def OAMA_FLAGS  rb ; 3
    def OAMB_PRI     equ 7 ; whether the OBJ is drawn above BG colors 1-3
    def OAMB_YFLIP   equ 6 ; whether the whole OBJ is flipped vertically
    def OAMB_XFLIP   equ 5 ; whether the whole OBJ is flipped horizontally
    def OAMB_PAL1    equ 4 ; (DMG only) which of the two palettes the OBJ uses
    def OAMB_BANK1   equ 3 ; (CGB only) which VRAM bank the OBJ takes its tile(s) from
    def OAMF_PALMASK equ %00000_111 ; (CGB only) which palette the OBJ uses
        def OAMF_PRI   equ 1 << OAMB_PRI
        def OAMF_YFLIP equ 1 << OAMB_YFLIP
        def OAMF_XFLIP equ 1 << OAMB_XFLIP
        def OAMF_PAL0  equ 0 << OAMB_PAL1
        def OAMF_PAL1  equ 1 << OAMB_PAL1
        def OAMF_BANK0 equ 0 << OAMB_BANK1
        def OAMF_BANK1 equ 1 << OAMB_BANK1
def OBJ_B     rb 0 ; size of OBJ in bytes = 4

def OAM_COUNT equ 40 ; how many OBJs there are room for in OAM
def OAM_B     equ OBJ_B * OAM_COUNT


;******************************************************************************
; Interrupt vector addresses
;******************************************************************************

def INT_HANDLER_VBLANK equ $0040 ; VBlank interrupt handler address
def INT_HANDLER_STAT   equ $0048 ; STAT   interrupt handler address
def INT_HANDLER_TIMER  equ $0050 ; timer  interrupt handler address
def INT_HANDLER_SERIAL equ $0058 ; serial interrupt handler address
def INT_HANDLER_JOYPAD equ $0060 ; joypad interrupt handler address


;******************************************************************************
; Boot-up register values
;******************************************************************************

; Register A = CPU type
def BOOTUP_A_DMG equ $01
def BOOTUP_A_CGB equ $11 ; CGB or AGB
def BOOTUP_A_MGB equ $FF
    def BOOTUP_A_SGB  equ BOOTUP_A_DMG
    def BOOTUP_A_SGB2 equ BOOTUP_A_MGB

; Register B = CPU qualifier (if A is BOOTUP_A_CGB)
def BOOTUPB_B_AGB equ 0
    def BOOTUP_B_CGB equ 0 << BOOTUPB_B_AGB
    def BOOTUP_B_AGB equ 1 << BOOTUPB_B_AGB


;******************************************************************************
; Aliases
;******************************************************************************

; Prefer the standard names to these aliases, which may be official but are
; less directly meaningful or human-readable.

def rP1 equ rJOYP
    def P1F_GET_BTN  equ JOYP_GET_BTN
    def P1F_GET_DPAD equ JOYP_GET_DPAD
    def P1F_GET_NONE equ JOYP_GET_NONE
    def P1F_5 equ JOYP_GET_DPAD
    def P1F_4 equ JOYP_GET_BTN
    def P1F_3 equ JOYPF_DOWN
    def P1F_2 equ JOYPF_UP
    def P1F_1 equ JOYPF_LEFT
    def P1F_0 equ JOYPF_RIGHT

def rNR10 equ rAUD1SWEEP
def rNR11 equ rAUD1LEN
def rNR12 equ rAUD1ENV
def rNR13 equ rAUD1LOW
def rNR14 equ rAUD1HIGH
def rNR21 equ rAUD2LEN
def rNR22 equ rAUD2ENV
def rNR23 equ rAUD2LOW
def rNR24 equ rAUD2HIGH
def rNR30 equ rAUD3ENA
def rNR31 equ rAUD3LEN
def rNR32 equ rAUD3LEVEL
def rNR33 equ rAUD3LOW
def rNR34 equ rAUD3HIGH
def rNR41 equ rAUD4LEN
def rNR42 equ rAUD4ENV
def rNR43 equ rAUD4POLY
def rNR44 equ rAUD4GO
def rNR50 equ rAUDVOL
def rNR51 equ rAUDTERM
def rNR52 equ rAUDENA

def rKEY1 equ rSPD
    def KEY1F_DBLSPEED equ SPDF_DBLSPEED
    def KEY1F_PREPARE  equ SPDF_PREPARE

def rHDMA1 equ rVDMA_SRC_HIGH
def rHDMA2 equ rVDMA_SRC_LOW
def rHDMA3 equ rVDMA_DEST_HIGH
def rHDMA4 equ rVDMA_DEST_LOW
def rHDMA5 equ rVDMA_LEN
    def HDMA5B_MODE equ VDMA_LENB_MODE
        def HDMA5F_MODE_GP  equ VDMA_LENF_MODE_GP
        def HDMA5F_MODE_HBL equ VDMA_LENF_MODE_HBL
        def HDMA5F_BUSY     equ VDMA_LENF_BUSY

def rBCPS equ rBGPI
    def BCPSB_AUTOINC equ BGPIB_AUTOINC
    def BCPSF_AUTOINC equ BGPIF_AUTOINC
def rBCPD equ rBGPD

def rOCPS equ rOBPI
    def OCPSB_AUTOINC equ OBPIB_AUTOINC
    def OCPSF_AUTOINC equ OBPIF_AUTOINC
def rOCPD equ rOBPD

def rSVBK equ rWBK
def rSMBK equ rWBK


;******************************************************************************
; (deprecated) Memory regions
;******************************************************************************

; These values are deprecated; please use RGBASM and RGBLINK features instead.
; Note that the value of `STARTOF(<section_type>)` is determined at link time.

def _ROM     equ $0000 ; $0000-$3FFF / $0000-$7FFF (prefer `STARTOF(ROM0)`)
def _ROMBANK equ $4000 ; $4000-$7FFF               (prefer `STARTOF(ROMX)`)
def _VRAM    equ $8000 ; $8000-$9FFF               (prefer `STARTOF(VRAM)`)
def _SRAM    equ $A000 ; $A000-$BFFF               (prefer `STARTOF(SRAM)`)
def _RAM     equ $C000 ; $C000-$CFFF / $C000-$DFFF (prefer `STARTOF(WRAM0)`)
def _RAMBANK equ $D000 ; $D000-$DFFF               (prefer `STARTOF(WRAMX)`)
def _OAMRAM  equ $FE00 ; $FE00-$FE9F               (prefer `STARTOF(OAM)`)
def _IO      equ $FF00 ; $FF00-$FF7F, $FFFF        (prefer `ldh [c]` to `ld [_IO+c]`)
def _HRAM    equ $FF80 ; $FF80-$FFFE               (prefer `STARTOF(HRAM)`)

def _VRAM8000 equ _VRAM
def _VRAM8800 equ _VRAM + $800
def _VRAM9000 equ _VRAM + $1000


;******************************************************************************
; (deprecated) Cartridge header
;******************************************************************************

; These values are deprecated; please use RGBFIX instead.
; Zero-filled space can be reserved for fixable header values like this:
;
;     SECTION "Cartridge header", ROM0[$0100]
;         nop :: jp $0150  ; Entry point ($0100-$0104)
;         ds $150 - @, $00 ; Header ($0104-$014FF) filled with $00s for RGBFIX to populate

; -- Nintendo logo ($0104-$0133) ----------------------------------------------
; Prefer `rgbfix -f/--fix-spec l` for the official logo, or `rgbfix -L <logo_file>` for a custom one
MACRO NINTENDO_LOGO
    db $CE,$ED,$66,$66,$CC,$0D,$00,$0B,$03,$73,$00,$83,$00,$0C,$00,$0D
    db $00,$08,$11,$1F,$88,$89,$00,$0E,$DC,$CC,$6E,$E6,$DD,$DD,$D9,$99
    db $BB,$BB,$67,$63,$6E,$0E,$EC,$CC,$DD,$DC,$99,$9F,$BB,$B9,$33,$3E
ENDM

; -- CGB compatibility code ($0143) -------------------------------------------
def CART_COMPATIBLE_DMG     equ $00 ; default value if header is zero-filled
def CART_COMPATIBLE_DMG_GBC equ $80 ; prefer `rgbfix -c/--color-compatible`
def CART_COMPATIBLE_GBC     equ $C0 ; prefer `rgbfix -C/--color-only`

; -- SGB flag ($0146) ---------------------------------------------------------
def CART_INDICATOR_GB  equ $00 ; default value if header is zero-filled
def CART_INDICATOR_SGB equ $03 ; prefer `rgblink -s/--sgb-compatible`

; -- Cartridge type ($0147) ---------------------------------------------------
; Prefer `rgblink -m/--mbc_type <mbc_type>`
def CART_ROM                     equ $00
def CART_ROM_MBC1                equ $01
def CART_ROM_MBC1_RAM            equ $02
def CART_ROM_MBC1_RAM_BAT        equ $03
def CART_ROM_MBC2                equ $05
def CART_ROM_MBC2_BAT            equ $06
def CART_ROM_RAM                 equ $08
def CART_ROM_RAM_BAT             equ $09
def CART_ROM_MMM01               equ $0B
def CART_ROM_MMM01_RAM           equ $0C
def CART_ROM_MMM01_RAM_BAT       equ $0D
def CART_ROM_MBC3_BAT_RTC        equ $0F
def CART_ROM_MBC3_RAM_BAT_RTC    equ $10
def CART_ROM_MBC3                equ $11
def CART_ROM_MBC3_RAM            equ $12
def CART_ROM_MBC3_RAM_BAT        equ $13
def CART_ROM_MBC5                equ $19
def CART_ROM_MBC5_RAM            equ $1A
def CART_ROM_MBC5_RAM_BAT        equ $1B
def CART_ROM_MBC5_RUMBLE         equ $1C
def CART_ROM_MBC5_RAM_RUMBLE     equ $1D
def CART_ROM_MBC5_RAM_BAT_RUMBLE equ $1E
def CART_ROM_MBC7_RAM_BAT_GYRO   equ $22
def CART_ROM_POCKET_CAMERA       equ $FC
def CART_ROM_BANDAI_TAMA5        equ $FD
def CART_ROM_HUDSON_HUC3         equ $FE
def CART_ROM_HUDSON_HUC1         equ $FF

; -- ROM size ($0148) ---------------------------------------------------------
; Prefer `rgbfix -p/--pad_value <pad_value>`, which pads to the smallest valid size
def CART_ROM_32KB   equ $00 ;   2 banks
def CART_ROM_64KB   equ $01 ;   4 banks
def CART_ROM_128KB  equ $02 ;   8 banks
def CART_ROM_256KB  equ $03 ;  16 banks
def CART_ROM_512KB  equ $04 ;  32 banks
def CART_ROM_1024KB equ $05 ;  64 banks
def CART_ROM_2048KB equ $06 ; 128 banks
def CART_ROM_4096KB equ $07 ; 256 banks
def CART_ROM_8192KB equ $08 ; 512 banks
def CART_ROM_1152KB equ $52 ;  72 banks
def CART_ROM_1280KB equ $53 ;  80 banks
def CART_ROM_1536KB equ $54 ;  96 banks

; -- SRAM size ($0149) --------------------------------------------------------
; Prefer `rgbfix -r/--ram_size <ram_size>`
def CART_SRAM_NONE  equ 0 ; none
def CART_SRAM_2KB   equ 1 ;  1 incomplete bank (homebrew only)
def CART_SRAM_8KB   equ 2 ;  1 bank
def CART_SRAM_32KB  equ 3 ;  4 banks
def CART_SRAM_128KB equ 4 ; 16 banks

; -- Destination code ($014A) -------------------------------------------------
def CART_DEST_JAPANESE     equ $00 ; default value if header is zero-filled
def CART_DEST_NON_JAPANESE equ $01 ; prefer `rgbfix -j/--non-japanese`


;******************************************************************************
; Deprecated constants
;******************************************************************************

; These values are deprecated; please avoid using them.

def LCDCB_BG8000 equ LCDCB_BLKS
    def LCDCF_BG8800 equ LCDCF_BLK21
    def LCDCF_BG8000 equ LCDCF_BLK01

def IEB_HILO equ IEB_JOYPAD
    def IEF_HILO equ IEF_JOYPAD
def IEF_LCDC equ IEF_STAT

def sizeof_OAM_ATTRS equ OBJ_B

endc ; HARDWARE_INC