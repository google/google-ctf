#include "../uxn.h"
#include "mouse.h"

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

void
mouse_down(Uxn *u, Uint8 *d, Uint8 mask)
{
	d[6] |= mask;
	uxn_eval(u, PEEK2(d));
}

void
mouse_up(Uxn *u, Uint8 *d, Uint8 mask)
{
	d[6] &= (~mask);
	uxn_eval(u, PEEK2(d));
}

void
mouse_pos(Uxn *u, Uint8 *d, Uint16 x, Uint16 y)
{
	*(d + 2) = x >> 8, *(d + 3) = x;
	*(d + 4) = y >> 8, *(d + 5) = y;
	uxn_eval(u, PEEK2(d));
}

void
mouse_scroll(Uxn *u, Uint8 *d, Uint16 x, Uint16 y)
{
	*(d + 0xa) = x >> 8, *(d + 0xb) = x;
	*(d + 0xc) = -y >> 8, *(d + 0xd) = -y;
	uxn_eval(u, PEEK2(d));
	*(d + 0xa) = *(d + 0xb) = *(d + 0xc) = *(d + 0xd) = 0;
}
