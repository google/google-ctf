#include "../uxn.h"
#include "controller.h"

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

void
controller_down(Uxn *u, Uint8 *d, Uint8 mask)
{
	if(mask) {
		d[2] |= mask;
		uxn_eval(u, PEEK2(d));
	}
}

void
controller_up(Uxn *u, Uint8 *d, Uint8 mask)
{
	if(mask) {
		d[2] &= (~mask);
		uxn_eval(u, PEEK2(d));
	}
}

void
controller_key(Uxn *u, Uint8 *d, Uint8 key)
{
	if(key) {
		d[3] = key;
		uxn_eval(u, PEEK2(d));
		d[3] = 0x00;
	}
}
