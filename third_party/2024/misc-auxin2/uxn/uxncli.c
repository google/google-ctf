#include <stdio.h>
#include <stdlib.h>

#include "uxn.h"
#include "devices/system.h"
#include "devices/console.h"
#include "devices/file.h"
#include "devices/datetime.h"

/*
Copyright (c) 2021-2024 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

Uint8
emu_dei(Uxn *u, Uint8 addr)
{
	switch(addr & 0xf0) {
	case 0x00: return system_dei(u, addr);
	case 0xc0: return datetime_dei(u, addr);
	}
	return u->dev[addr];
}

void
emu_deo(Uxn *u, Uint8 addr, Uint8 value)
{
	Uint8 p = addr & 0x0f, d = addr & 0xf0;
	u->dev[addr] = value;
	switch(d) {
	case 0x00: system_deo(u, &u->dev[d], p); break;
	case 0x10: console_deo(&u->dev[d], p); break;
	case 0xa0: file_deo(0, u->ram, &u->dev[d], p); break;
	case 0xb0: file_deo(1, u->ram, &u->dev[d], p); break;
	}
}

int
main(int argc, char **argv)
{
	int i = 1;
	Uxn u = {0};
	Uint8 dev[0x100] = {0};
	u.dev = dev;
	if(i == argc)
		return system_error("usage:", "uxncli [-v] file.rom [args..]");
	if(argv[i][0] == '-' && argv[i][1] == 'v')
		return system_error("Uxncli - Varvara Emulator(CLI)", "18 Mar 2024.");
	if(!system_init(&u, (Uint8 *)calloc(0x10000 * RAM_PAGES, sizeof(Uint8)), argv[i++]))
		return system_error("Init", "Failed to initialize uxn.");
	/* eval */
	u.dev[0x17] = argc - i;
	if(uxn_eval(&u, PAGE_PROGRAM) && PEEK2(u.dev + 0x10)) {
		console_listen(&u, i, argc, argv);
		while(!u.dev[0x0f]) {
			int c = fgetc(stdin);
			if(c == EOF) {
				console_input(&u, 0x00, CONSOLE_END);
				break;
			}
			console_input(&u, (Uint8)c, CONSOLE_STD);
		}
	}
	free(u.ram);
	return u.dev[0x0f] & 0x7f;
}
