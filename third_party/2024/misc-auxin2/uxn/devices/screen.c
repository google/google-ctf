#include <stdlib.h>
#include <stdio.h>

#include "../uxn.h"
#include "screen.h"

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

UxnScreen uxn_screen;

/* c = !ch ? (color % 5 ? color >> 2 : 0) : color % 4 + ch == 1 ? 0 : (ch - 2 + (color & 3)) % 3 + 1; */

static Uint8 blending[][16] = {
	{0, 0, 0, 0, 1, 0, 1, 1, 2, 2, 0, 2, 3, 3, 3, 0},
	{0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3},
	{1, 2, 3, 1, 1, 2, 3, 1, 1, 2, 3, 1, 1, 2, 3, 1},
	{2, 3, 1, 2, 2, 3, 1, 2, 2, 3, 1, 2, 2, 3, 1, 2},
	{0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0}};

void
screen_change(Uint16 x1, Uint16 y1, Uint16 x2, Uint16 y2)
{
	if(x1 > uxn_screen.width && x2 > x1) return;
	if(y1 > uxn_screen.height && y2 > y1) return;
	if(x1 > x2) x1 = 0;
	if(y1 > y2) y1 = 0;
	if(x1 < uxn_screen.x1) uxn_screen.x1 = x1;
	if(y1 < uxn_screen.y1) uxn_screen.y1 = y1;
	if(x2 > uxn_screen.x2) uxn_screen.x2 = x2;
	if(y2 > uxn_screen.y2) uxn_screen.y2 = y2;
}

void
screen_fill(Uint8 *layer, int color)
{
	int i, length = uxn_screen.width * uxn_screen.height;
	for(i = 0; i < length; i++)
		layer[i] = color;
}

void
screen_rect(Uint8 *layer, Uint16 x1, Uint16 y1, Uint16 x2, Uint16 y2, int color)
{
	int row, x, y, w = uxn_screen.width, h = uxn_screen.height;
	for(y = y1; y < y2 && y < h; y++)
		for(x = x1, row = y * w; x < x2 && x < w; x++)
			layer[x + row] = color;
}

static void
screen_2bpp(Uint8 *layer, Uint8 *addr, Uint16 x1, Uint16 y1, Uint16 color, int fx, int fy)
{
	int w = uxn_screen.width, h = uxn_screen.height, opaque = blending[4][color];
	Uint16 y, ymod = (fy < 0 ? 7 : 0), ymax = y1 + ymod + fy * 8;
	Uint16 x, xmod = (fx > 0 ? 7 : 0), xmax = x1 + xmod - fx * 8;
	for(y = y1 + ymod; y != ymax; y += fy, addr++) {
		int c = addr[0] | (addr[8] << 8), row = y * w;
		if(y < h)
			for(x = x1 + xmod; x != xmax; x -= fx, c >>= 1) {
				Uint8 ch = (c & 1) | ((c >> 7) & 2);
				if(x < w && (opaque || ch))
					layer[x + row] = blending[ch][color];
			}
	}
}

static void
screen_1bpp(Uint8 *layer, Uint8 *addr, Uint16 x1, Uint16 y1, Uint16 color, int fx, int fy)
{
	int w = uxn_screen.width, h = uxn_screen.height, opaque = blending[4][color];
	Uint16 y, ymod = (fy < 0 ? 7 : 0), ymax = y1 + ymod + fy * 8;
	Uint16 x, xmod = (fx > 0 ? 7 : 0), xmax = x1 + xmod - fx * 8;
	for(y = y1 + ymod; y != ymax; y += fy) {
		int c = *addr++, row = y * w;
		if(y < h)
			for(x = x1 + xmod; x != xmax; x -= fx, c >>= 1) {
				Uint8 ch = c & 1;
				if(x < w && (opaque || ch))
					layer[x + row] = blending[ch][color];
			}
	}
}

/* clang-format off */

static Uint8 icons[] = {
	0x00, 0x7c, 0x82, 0x82, 0x82, 0x82, 0x82, 0x7c, 0x00, 0x30, 0x10, 0x10, 0x10, 0x10, 0x10, 
	0x10, 0x00, 0x7c, 0x82, 0x02, 0x7c, 0x80, 0x80, 0xfe, 0x00, 0x7c, 0x82, 0x02, 0x1c, 0x02, 
	0x82, 0x7c, 0x00, 0x0c, 0x14, 0x24, 0x44, 0x84, 0xfe, 0x04, 0x00, 0xfe, 0x80, 0x80, 0x7c, 
	0x02, 0x82, 0x7c, 0x00, 0x7c, 0x82, 0x80, 0xfc, 0x82, 0x82, 0x7c, 0x00, 0x7c, 0x82, 0x02, 
	0x1e, 0x02, 0x02, 0x02, 0x00, 0x7c, 0x82, 0x82, 0x7c, 0x82, 0x82, 0x7c, 0x00, 0x7c, 0x82, 
	0x82, 0x7e, 0x02, 0x82, 0x7c, 0x00, 0x7c, 0x82, 0x02, 0x7e, 0x82, 0x82, 0x7e, 0x00, 0xfc, 
	0x82, 0x82, 0xfc, 0x82, 0x82, 0xfc, 0x00, 0x7c, 0x82, 0x80, 0x80, 0x80, 0x82, 0x7c, 0x00, 
	0xfc, 0x82, 0x82, 0x82, 0x82, 0x82, 0xfc, 0x00, 0x7c, 0x82, 0x80, 0xf0, 0x80, 0x82, 0x7c,
	0x00, 0x7c, 0x82, 0x80, 0xf0, 0x80, 0x80, 0x80 };
static Uint8 arrow[] = {
	0x00, 0x00, 0x00, 0xfe, 0x7c, 0x38, 0x10, 0x00 };

/* clang-format on */

static void
draw_byte(Uint8 b, Uint16 x, Uint16 y, Uint8 color)
{
	screen_1bpp(uxn_screen.fg, &icons[(b >> 4) << 3], x, y, color, 1, 1);
	screen_1bpp(uxn_screen.fg, &icons[(b & 0xf) << 3], x + 8, y, color, 1, 1);
	screen_change(x, y, x + 0x10, y + 0x8);
}

static void
screen_debugger(Uxn *u)
{
	int i;
	for(i = 0; i < 0x08; i++) {
		Uint8 pos = u->wst.ptr - 4 + i;
		Uint8 color = i > 4 ? 0x01 : !pos ? 0xc
			: i == 4                      ? 0x8
										  : 0x2;
		draw_byte(u->wst.dat[pos], i * 0x18 + 0x8, uxn_screen.height - 0x18, color);
	}
	for(i = 0; i < 0x08; i++) {
		Uint8 pos = u->rst.ptr - 4 + i;
		Uint8 color = i > 4 ? 0x01 : !pos ? 0xc
			: i == 4                      ? 0x8
										  : 0x2;
		draw_byte(u->rst.dat[pos], i * 0x18 + 0x8, uxn_screen.height - 0x10, color);
	}
	screen_1bpp(uxn_screen.fg, &arrow[0], 0x68, uxn_screen.height - 0x20, 3, 1, 1);
	for(i = 0; i < 0x20; i++)
		draw_byte(u->ram[i], (i & 0x7) * 0x18 + 0x8, ((i >> 3) << 3) + 0x8, 1 + !!u->ram[i]);
}

void
screen_palette(Uint8 *addr)
{
	int i, shift;
	for(i = 0, shift = 4; i < 4; ++i, shift ^= 4) {
		Uint8
			r = (addr[0 + i / 2] >> shift) & 0xf,
			g = (addr[2 + i / 2] >> shift) & 0xf,
			b = (addr[4 + i / 2] >> shift) & 0xf;
		uxn_screen.palette[i] = 0x0f000000 | r << 16 | g << 8 | b;
		uxn_screen.palette[i] |= uxn_screen.palette[i] << 4;
	}
	screen_change(0, 0, uxn_screen.width, uxn_screen.height);
}

void
screen_resize(Uint16 width, Uint16 height)
{
	Uint8 *bg, *fg;
	Uint32 *pixels = NULL;
	if(width < 0x8 || height < 0x8 || width >= 0x800 || height >= 0x800)
		return;
	if(uxn_screen.width == width && uxn_screen.height == height)
		return;
	bg = malloc(width * height), fg = malloc(width * height);
	if(bg && fg)
		pixels = realloc(uxn_screen.pixels, width * height * sizeof(Uint32));
	if(!bg || !fg || !pixels) {
		free(bg), free(fg);
		return;
	}
	free(uxn_screen.bg), free(uxn_screen.fg);
	uxn_screen.bg = bg, uxn_screen.fg = fg;
	uxn_screen.pixels = pixels;
	uxn_screen.width = width, uxn_screen.height = height;
	screen_fill(uxn_screen.bg, 0), screen_fill(uxn_screen.fg, 0);
	emu_resize(width, height);
	screen_change(0, 0, width, height);
}

void
screen_redraw(Uxn *u)
{
	int i, j, o, y;
	Uint8 *fg = uxn_screen.fg, *bg = uxn_screen.bg;
	Uint16 w = uxn_screen.width, h = uxn_screen.height;
	Uint16 x1 = uxn_screen.x1, y1 = uxn_screen.y1;
	Uint16 x2 = uxn_screen.x2 > w ? w : uxn_screen.x2, y2 = uxn_screen.y2 > h ? h : uxn_screen.y2;
	Uint32 palette[16], *pixels = uxn_screen.pixels;
	uxn_screen.x1 = uxn_screen.y1 = 0xffff;
	uxn_screen.x2 = uxn_screen.y2 = 0;
	if(u->dev[0x0e])
		screen_debugger(u);
	for(i = 0; i < 16; i++)
		palette[i] = uxn_screen.palette[(i >> 2) ? (i >> 2) : (i & 3)];
	for(y = y1; y < y2; y++)
		for(o = y * w, i = x1 + o, j = x2 + o; i < j; i++)
			pixels[i] = palette[fg[i] << 2 | bg[i]];
}

/* screen registers */

static Uint16 rX, rY, rA, rMX, rMY, rMA, rML, rDX, rDY;

Uint8
screen_dei(Uxn *u, Uint8 addr)
{
	switch(addr) {
	case 0x22: return uxn_screen.width >> 8;
	case 0x23: return uxn_screen.width;
	case 0x24: return uxn_screen.height >> 8;
	case 0x25: return uxn_screen.height;
	case 0x28: return rX >> 8;
	case 0x29: return rX;
	case 0x2a: return rY >> 8;
	case 0x2b: return rY;
	case 0x2c: return rA >> 8;
	case 0x2d: return rA;
	default: return u->dev[addr];
	}
}

void
screen_deo(Uint8 *ram, Uint8 *d, Uint8 port)
{
	switch(port) {
	case 0x3: screen_resize(PEEK2(d + 2), uxn_screen.height); return;
	case 0x5: screen_resize(uxn_screen.width, PEEK2(d + 4)); return;
	case 0x6: rMX = d[0x6] & 0x1, rMY = d[0x6] & 0x2, rMA = d[0x6] & 0x4, rML = d[0x6] >> 4, rDX = rMX << 3, rDY = rMY << 2; return;
	case 0x8:
	case 0x9: rX = (d[0x8] << 8) | d[0x9]; return;
	case 0xa:
	case 0xb: rY = (d[0xa] << 8) | d[0xb]; return;
	case 0xc:
	case 0xd: rA = (d[0xc] << 8) | d[0xd]; return;
	case 0xe: {
		Uint8 ctrl = d[0xe];
		Uint8 color = ctrl & 0x3;
		Uint8 *layer = ctrl & 0x40 ? uxn_screen.fg : uxn_screen.bg;
		/* fill mode */
		if(ctrl & 0x80) {
			Uint16 x1, y1, x2, y2;
			if(ctrl & 0x10)
				x1 = 0, x2 = rX;
			else
				x1 = rX, x2 = uxn_screen.width;
			if(ctrl & 0x20)
				y1 = 0, y2 = rY;
			else
				y1 = rY, y2 = uxn_screen.height;
			screen_rect(layer, x1, y1, x2, y2, color);
			screen_change(x1, y1, x2, y2);
		}
		/* pixel mode */
		else {
			Uint16 w = uxn_screen.width;
			if(rX < w && rY < uxn_screen.height)
				layer[rX + rY * w] = color;
			screen_change(rX, rY, rX + 1, rY + 1);
			if(rMX) rX++;
			if(rMY) rY++;
		}
		return;
	}
	case 0xf: {
		Uint8 i;
		Uint8 ctrl = d[0xf];
		Uint8 twobpp = !!(ctrl & 0x80);
		Uint8 color = ctrl & 0xf;
		Uint8 *layer = ctrl & 0x40 ? uxn_screen.fg : uxn_screen.bg;
		int fx = ctrl & 0x10 ? -1 : 1;
		int fy = ctrl & 0x20 ? -1 : 1;
		Uint16 dxy = rDX * fy, dyx = rDY * fx, addr_incr = rMA << (1 + twobpp);
		if(twobpp)
			for(i = 0; i <= rML; i++, rA += addr_incr)
				screen_2bpp(layer, &ram[rA], rX + dyx * i, rY + dxy * i, color, fx, fy);
		else
			for(i = 0; i <= rML; i++, rA += addr_incr)
				screen_1bpp(layer, &ram[rA], rX + dyx * i, rY + dxy * i, color, fx, fy);
		screen_change(rX, rY, rX + dyx * rML + 8, rY + dxy * rML + 8);
		if(rMX) rX += rDX * fx;
		if(rMY) rY += rDY * fy;
		return;
	}
	}
}
