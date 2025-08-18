.text
.org 0

.set START, _start
.set INT, _int
.set HBLANK, _int
.set VBLANK, _vblank

.long 0x0
.long START
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long HBLANK
.long INT
.long VBLANK
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT
.long INT

.ascii  "SEGA MEGADRIVE  "
.ascii  "(C)2025.AUG     "
.ascii  "HACKCELER8      "
.ascii  "                "
.ascii  "                "
.ascii  "HACKCELER8      "
.ascii  "                "
.ascii  "                "
.ascii  "GM MK-0000 -01"
.short  0x0000
.ascii  "J6              "
.long   0x00000000, 0x0007ffff
.long   0x00ff0000, 0x00ffffff
.ascii  "            "
.ascii  "    "
.ascii  "        "
.ascii  "        "
.ascii  "                "
.ascii  "                "
.ascii  "F               "

.global vblank
_vblank:
  jsr vblank
  rte

.global _start
.global game_main
_start:
  move.l #_stack_top, %sp
  move.w #0x2500, %sr
  jsr _init_runtime
  jsr game_main

.global abort
abort:
  bra abort

_int:
  rte

.global wait_for_interrupt
wait_for_interrupt:
  stop #0x2500
  rts
