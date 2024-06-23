#include <stdio.h>
#include <stdlib.h>

#include "../uxn.h"
#include "system.h"

/*
Copyright (c) 2022-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

char *boot_rom;
Uint16 dev_vers[0x10];

static int
system_load(Uxn *u, char *filename)
{
	int l, i = 0;
	FILE *f = fopen(filename, "rb");
	if(!f)
		return 0;
	l = fread(&u->ram[PAGE_PROGRAM], 0x10000 - PAGE_PROGRAM, 1, f);
	while(l && ++i < RAM_PAGES)
		l = fread(u->ram + 0x10000 * i, 0x10000, 1, f);
	fclose(f);
	return 1;
}

static void
system_print(Stack *s)
{
	Uint8 i;
	for(i = s->ptr - 7; i != (Uint8)(s->ptr + 1); i++)
		fprintf(stderr, "%02x%c", s->dat[i], i == 0 ? '|' : ' ');
	fprintf(stderr, "< \n");
}

static void
system_zero(Uxn *u, int soft)
{
	int i;
	for(i = PAGE_PROGRAM * soft; i < 0x10000; i++)
		u->ram[i] = 0;
	for(i = 0x0; i < 0x100; i++)
		u->dev[i] = 0;
	u->wst.ptr = u->rst.ptr = 0;
}

void
system_inspect(Uxn *u)
{
	fprintf(stderr, "WST "), system_print(&u->wst);
	fprintf(stderr, "RST "), system_print(&u->rst);
}

int
system_error(char *msg, const char *err)
{
	fprintf(stderr, "%s %s\n", msg, err);
	fflush(stderr);
	return 0;
}

void
system_reboot(Uxn *u, char *rom, int soft)
{
	system_zero(u, soft);
	if(system_load(u, boot_rom))
		if(uxn_eval(u, PAGE_PROGRAM))
			boot_rom = rom;
}

int
system_init(Uxn *u, Uint8 *ram, char *rom)
{
	u->ram = ram;
	system_zero(u, 0);
	if(!system_load(u, rom))
		if(!system_load(u, "boot.rom"))
			return system_error("Init", "Failed to load rom.");
	boot_rom = rom;
	return 1;
}

/* IO */

Uint8
system_dei(Uxn *u, Uint8 addr)
{
	switch(addr) {
	case 0x4: return u->wst.ptr;
	case 0x5: return u->rst.ptr;
	default: return u->dev[addr];
	}
}

void
system_deo(Uxn *u, Uint8 *d, Uint8 port)
{
	Uint8 *ram;
	Uint16 addr;
	switch(port) {
	case 0x3:
		ram = u->ram;
		addr = PEEK2(d + 2);
		if(ram[addr] == 0x0) {
			Uint8 value = ram[addr + 7];
			Uint16 i, length = PEEK2(ram + addr + 1);
			Uint16 dst_page = PEEK2(ram + addr + 3), dst_addr = PEEK2(ram + addr + 5);
			int dst = (dst_page % RAM_PAGES) * 0x10000;
			for(i = 0; i < length; i++)
				ram[dst + (Uint16)(dst_addr + i)] = value;
		} else if(ram[addr] == 0x1) {
			Uint16 i, length = PEEK2(ram + addr + 1);
			Uint16 a_page = PEEK2(ram + addr + 3), a_addr = PEEK2(ram + addr + 5);
			Uint16 b_page = PEEK2(ram + addr + 7), b_addr = PEEK2(ram + addr + 9);
			int src = (a_page % RAM_PAGES) * 0x10000, dst = (b_page % RAM_PAGES) * 0x10000;
			for(i = 0; i < length; i++)
				ram[dst + (Uint16)(b_addr + i)] = ram[src + (Uint16)(a_addr + i)];
		} else if(ram[addr] == 0x2) {
			Uint16 i, length = PEEK2(ram + addr + 1);
			Uint16 a_page = PEEK2(ram + addr + 3), a_addr = PEEK2(ram + addr + 5);
			Uint16 b_page = PEEK2(ram + addr + 7), b_addr = PEEK2(ram + addr + 9);
			int src = (a_page % RAM_PAGES) * 0x10000, dst = (b_page % RAM_PAGES) * 0x10000;
			for(i = length - 1; i != 0xffff; i--)
				ram[dst + (Uint16)(b_addr + i)] = ram[src + (Uint16)(a_addr + i)];
		} else
			fprintf(stderr, "Unknown Expansion Command 0x%02x\n", ram[addr]);
		break;
	case 0x4:
		u->wst.ptr = d[4];
		break;
	case 0x5:
		u->rst.ptr = d[5];
		break;
	case 0xe:
		system_inspect(u);
		break;
	}
}
