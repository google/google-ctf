#include "uxn.h"
#include <stdio.h>
/*
Copyright (u) 2022-2023 Devine Lu Linvega, Andrew Alderwick, Andrew Richards

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

/* Registers
[ Z ][ Y ][ X ][ L ][ N ][ T ] <
[ . ][ . ][ . ][   H2   ][ . ] <
[   L2   ][   N2   ][   T2   ] <
*/

#define T *(s->dat + s->ptr)
#define N *(s->dat + (Uint8)(s->ptr - 1))
#define L *(s->dat + (Uint8)(s->ptr - 2))
#define X *(s->dat + (Uint8)(s->ptr - 3))
#define Y *(s->dat + (Uint8)(s->ptr - 4))
#define Z *(s->dat + (Uint8)(s->ptr - 5))
#define T2 (N << 8 | T)
#define H2 (L << 8 | N)
#define N2 (X << 8 | L)
#define L2 (Z << 8 | Y)
#define T2_(v) { r = (v); T = r; N = r >> 8; }
#define N2_(v) { r = (v); L = r; X = r >> 8; }
#define L2_(v) { r = (v); Y = r; Z = r >> 8; }
#define FLIP      { s = ins & 0x40 ? &u->wst : &u->rst; }
#define SHIFT(y)  { s->ptr += (y); }
#define SET(x, y) { SHIFT((ins & 0x80) ? x + y : y) }

int
uxn_eval(Uxn *u, Uint16 pc)
{
	Uint16 t, n, l, r;
	Uint8 *ram = u->ram, *rr;
	if(!pc || u->dev[0x0f]) return 0;
	for(;;) {
		Uint8 ins = ram[pc++];
		Stack *s = ins & 0x40 ? &u->rst : &u->wst;
	    /*printf("%04x: %02x [ %02x %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x %02x ] [ %02x %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x %02x ]\n", pc-1, ins,
	    *(u->wst.dat + (Uint8)(u->wst.ptr + 6)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr + 5)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr + 4)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr + 3)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr + 2)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr + 1)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr - 1)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr - 2)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr - 3)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr - 4)),
	    *(u->wst.dat + (Uint8)(u->wst.ptr - 5)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr + 6)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr + 5)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr + 4)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr + 3)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr + 2)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr + 1)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr - 1)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr - 2)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr - 3)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr - 4)),
	    *(u->rst.dat + (Uint8)(u->rst.ptr - 5)));*/
		switch(ins & 0x3f) {
		/* IMM */
		case 0x00: case 0x20:
			switch(ins) {
			case 0x00: /* BRK  */                       return 1;
			case 0x20: /* JCI  */ t=T;        SHIFT(-1) if(!t) { pc += 2; break; } /* fall-through */
			case 0x40: /* JMI  */                       rr = ram + pc; pc += 2 + PEEK2(rr); break;
			case 0x60: /* JSI  */             SHIFT( 2) rr = ram + pc; pc += 2; T2_(pc); pc += PEEK2(rr); break;
			case 0x80: /* LIT  */ case 0xc0:  SHIFT( 1) T = ram[pc++]; break;
			case 0xa0: /* LIT2 */ case 0xe0:  SHIFT( 2) N = ram[pc++]; T = ram[pc++]; break;
			} break;
		/* ALU */
		case 0x01: /* INC  */ t=T;            SET(1, 0) T = t + 1; break;
		case 0x21: /* INC2 */ t=T2;           SET(2, 0) T2_(t + 1) break;
		case 0x02: /* POP  */                 SET(1,-1) break;
		case 0x22: /* POP2 */                 SET(2,-2) break;
		case 0x03: /* NIP  */ t=T;            SET(2,-1) T = t; break;
		case 0x23: /* NIP2 */ t=T2;           SET(4,-2) T2_(t) break;
		case 0x04: /* SWP  */ t=T;n=N;        SET(2, 0) T = n; N = t; break;
		case 0x24: /* SWP2 */ t=T2;n=N2;      SET(4, 0) T2_(n) N2_(t) break;
		case 0x05: /* ROT  */ t=T;n=N;l=L;    SET(3, 0) T = l; N = t; L = n; break;
		case 0x25: /* ROT2 */ t=T2;n=N2;l=L2; SET(6, 0) T2_(l) N2_(t) L2_(n) break;
		case 0x06: /* DUP  */ t=T;            SET(1, 1) T = t; N = t; break;
		case 0x26: /* DUP2 */ t=T2;           SET(2, 2) T2_(t) N2_(t) break;
		case 0x07: /* OVR  */ t=T;n=N;        SET(2, 1) T = n; N = t; L = n; break;
		case 0x27: /* OVR2 */ t=T2;n=N2;      SET(4, 2) T2_(n) N2_(t) L2_(n) break;
		case 0x08: /* EQU  */ t=T;n=N;        SET(2,-1) T = n == t; break;
		case 0x28: /* EQU2 */ t=T2;n=N2;      SET(4,-3) T = n == t; break;
		case 0x09: /* NEQ  */ t=T;n=N;        SET(2,-1) T = n != t; break;
		case 0x29: /* NEQ2 */ t=T2;n=N2;      SET(4,-3) T = n != t; break;
		case 0x0a: /* GTH  */ t=T;n=N;        SET(2,-1) T = n > t; break;
		case 0x2a: /* GTH2 */ t=T2;n=N2;      SET(4,-3) T = n > t; break;
		case 0x0b: /* LTH  */ t=T;n=N;        SET(2,-1) T = n < t; break;
		case 0x2b: /* LTH2 */ t=T2;n=N2;      SET(4,-3) T = n < t; break;
		case 0x0c: /* JMP  */ t=T;            SET(1,-1) pc += (Sint8)t; break;
		case 0x2c: /* JMP2 */ t=T2;           SET(2,-2) pc = t; break;
		case 0x0d: /* JCN  */ t=T;n=N;        SET(2,-2) if(n) pc += (Sint8)t; break;
		case 0x2d: /* JCN2 */ t=T2;n=L;       SET(3,-3) if(n) pc = t; break;
		case 0x0e: /* JSR  */ t=T;            SET(1,-1) FLIP SHIFT(2) T2_(pc) pc += (Sint8)t; break;
		case 0x2e: /* JSR2 */ t=T2;           SET(2,-2) FLIP SHIFT(2) T2_(pc) pc = t; break;
		case 0x0f: /* STH  */ t=T;            SET(1,-1) FLIP SHIFT(1) T = t; break;
		case 0x2f: /* STH2 */ t=T2;           SET(2,-2) FLIP SHIFT(2) T2_(t) break;
		case 0x10: /* LDZ  */ t=T;            SET(1, 0) T = ram[t]; break;
		case 0x30: /* LDZ2 */ t=T;            SET(1, 1) N = ram[t++]; T = ram[(Uint8)t]; break;
		case 0x11: /* STZ  */ t=T;n=N;        SET(2,-2) ram[t] = n; break;
		case 0x31: /* STZ2 */ t=T;n=H2;       SET(3,-3) ram[t++] = n >> 8; ram[(Uint8)t] = n; break;
		case 0x12: /* LDR  */ t=T;            SET(1, 0) r = pc + (Sint8)t; T = ram[r]; break;
		case 0x32: /* LDR2 */ t=T;            SET(1, 1) r = pc + (Sint8)t; N = ram[r++]; T = ram[r]; break;
		case 0x13: /* STR  */ t=T;n=N;        SET(2,-2) r = pc + (Sint8)t; ram[r] = n; break;
		case 0x33: /* STR2 */ t=T;n=H2;       SET(3,-3) r = pc + (Sint8)t; ram[r++] = n >> 8; ram[r] = n; break;
		case 0x14: /* LDA  */ t=T2;           SET(2,-1) T = ram[t]; break;
		case 0x34: /* LDA2 */ t=T2;           SET(2, 0) N = ram[t++]; T = ram[t]; break;
		case 0x15: /* STA  */ t=T2;n=L;       SET(3,-3) ram[t] = n; break;
		case 0x35: /* STA2 */ t=T2;n=N2;      SET(4,-4) ram[t++] = n >> 8; ram[t] = n; break;
		case 0x16: /* DEI  */ t=T;            SET(1, 0) T = emu_dei(u, t); break;
		case 0x36: /* DEI2 */ t=T;            SET(1, 1) N = emu_dei(u, t++); T = emu_dei(u, t); break;
		case 0x17: /* DEO  */ t=T;n=N;        SET(2,-2) emu_deo(u, t, n); break;
		case 0x37: /* DEO2 */ t=T;n=N;l=L;    SET(3,-3) emu_deo(u, t++, l); emu_deo(u, t, n); break;
		case 0x18: /* ADD  */ t=T;n=N;        SET(2,-1) T = n + t; break;
		case 0x38: /* ADD2 */ t=T2;n=N2;      SET(4,-2) T2_(n + t) break;
		case 0x19: /* SUB  */ t=T;n=N;        SET(2,-1) T = n - t; break;
		case 0x39: /* SUB2 */ t=T2;n=N2;      SET(4,-2) T2_(n - t) break;
		case 0x1a: /* MUL  */ t=T;n=N;        SET(2,-1) T = n * t; break;
		case 0x3a: /* MUL2 */ t=T2;n=N2;      SET(4,-2) T2_(n * t) break;
		case 0x1b: /* DIV  */ t=T;n=N;        SET(2,-1) T = t ? n / t : 0; break;
		case 0x3b: /* DIV2 */ t=T2;n=N2;      SET(4,-2) T2_(t ? n / t : 0) break;
		case 0x1c: /* AND  */ t=T;n=N;        SET(2,-1) T = n & t; break;
		case 0x3c: /* AND2 */ t=T2;n=N2;      SET(4,-2) T2_(n & t) break;
		case 0x1d: /* ORA  */ t=T;n=N;        SET(2,-1) T = n | t; break;
		case 0x3d: /* ORA2 */ t=T2;n=N2;      SET(4,-2) T2_(n | t) break;
		case 0x1e: /* EOR  */ t=T;n=N;        SET(2,-1) T = n ^ t; break;
		case 0x3e: /* EOR2 */ t=T2;n=N2;      SET(4,-2) T2_(n ^ t) break;
		case 0x1f: /* SFT  */ t=T;n=N;        SET(2,-1) T = n >> (t & 0xf) << (t >> 4); break;
		case 0x3f: /* SFT2 */ t=T;n=H2;       SET(3,-1) T2_(n >> (t & 0xf) << (t >> 4)) break;
		}
	}
}

