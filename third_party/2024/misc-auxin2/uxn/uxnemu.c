#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "uxn.h"

#pragma GCC diagnostic push
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
#include <SDL.h>
#include "devices/system.h"
#include "devices/console.h"
#include "devices/screen.h"
#include "devices/audio.h"
#include "devices/file.h"
#include "devices/controller.h"
#include "devices/mouse.h"
#include "devices/datetime.h"
#if defined(_WIN32) && defined(_WIN32_WINNT) && _WIN32_WINNT > 0x0602
#include <processthreadsapi.h>
#elif defined(_WIN32)
#include <windows.h>
#include <string.h>
#endif
#ifndef __plan9__
#define USED(x) (void)(x)
#endif
#pragma GCC diagnostic pop
#pragma clang diagnostic pop

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

#define PAD 2
#define PAD2 4
#define WIDTH 64 * 8
#define HEIGHT 40 * 8
#define TIMEOUT_MS 334

static SDL_Window *emu_window;
static SDL_Texture *emu_texture;
static SDL_Renderer *emu_renderer;
static SDL_Rect emu_viewport;
static SDL_AudioDeviceID audio_id;
static SDL_Thread *stdin_thread;

/* devices */

static int window_created, fullscreen, borderless;
static Uint32 stdin_event, audio0_event, zoom = 1;
static Uint64 exec_deadline, deadline_interval, ms_interval;

static int
clamp(int v, int min, int max)
{
	return v < min ? min : v > max ? max
								   : v;
}

static void
audio_deo(int instance, Uint8 *d, Uint8 port, Uxn *u)
{
	if(!audio_id) return;
	if(port == 0xf) {
		SDL_LockAudioDevice(audio_id);
		audio_start(instance, d, u);
		SDL_UnlockAudioDevice(audio_id);
		SDL_PauseAudioDevice(audio_id, 0);
	}
}

Uint8
emu_dei(Uxn *u, Uint8 addr)
{
	Uint8 p = addr & 0x0f, d = addr & 0xf0;
	switch(d) {
	case 0x00: return system_dei(u, addr);
	case 0x20: return screen_dei(u, addr);
	case 0x30: return audio_dei(0, &u->dev[d], p);
	case 0x40: return audio_dei(1, &u->dev[d], p);
	case 0x50: return audio_dei(2, &u->dev[d], p);
	case 0x60: return audio_dei(3, &u->dev[d], p);
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
	case 0x00:
		system_deo(u, &u->dev[d], p);
		if(p > 0x7 && p < 0xe) screen_palette(&u->dev[0x8]);
		break;
	case 0x10: console_deo(&u->dev[d], p); break;
	case 0x20: screen_deo(u->ram, &u->dev[0x20], p); break;
	case 0x30: audio_deo(0, &u->dev[d], p, u); break;
	case 0x40: audio_deo(1, &u->dev[d], p, u); break;
	case 0x50: audio_deo(2, &u->dev[d], p, u); break;
	case 0x60: audio_deo(3, &u->dev[d], p, u); break;
	case 0xa0: file_deo(0, u->ram, &u->dev[d], p); break;
	case 0xb0: file_deo(1, u->ram, &u->dev[d], p); break;
	}
}

/* Handlers */

void
audio_finished_handler(int instance)
{
	SDL_Event event;
	event.type = audio0_event + instance;
	SDL_PushEvent(&event);
}

static int
stdin_handler(void *p)
{
	SDL_Event event;
	USED(p);
	event.type = stdin_event;
	while(read(0, &event.cbutton.button, 1) > 0) {
		while(SDL_PushEvent(&event) < 0)
			SDL_Delay(25); /* slow down - the queue is most likely full */
	}
	return 0;
}

static void
set_window_size(SDL_Window *window, int w, int h)
{
	SDL_Point win_old;
	SDL_GetWindowSize(window, &win_old.x, &win_old.y);
	if(w == win_old.x && h == win_old.y) return;
	SDL_RenderClear(emu_renderer);
	SDL_SetWindowSize(window, w, h);
}

static void
set_zoom(Uint8 z, int win)
{
	if(z < 1) return;
	if(win)
		set_window_size(emu_window, (uxn_screen.width + PAD2) * z, (uxn_screen.height + PAD2) * z);
	zoom = z;
}

static void
set_fullscreen(int value, int win)
{
	Uint32 flags = 0; /* windowed mode; SDL2 has no constant for this */
	fullscreen = value;
	if(fullscreen)
		flags = SDL_WINDOW_FULLSCREEN_DESKTOP;
	if(win)
		SDL_SetWindowFullscreen(emu_window, flags);
}

static void
set_borderless(int value)
{
	if(fullscreen) return;
	borderless = value;
	SDL_SetWindowBordered(emu_window, !value);
}

static void
set_debugger(Uxn *u, int value)
{
	u->dev[0x0e] = value;
	screen_fill(uxn_screen.fg, 0);
	screen_redraw(u);
}

/* emulator primitives */

int
emu_resize(int width, int height)
{
	if(!window_created)
		return 0;
	if(emu_texture != NULL)
		SDL_DestroyTexture(emu_texture);
	SDL_RenderSetLogicalSize(emu_renderer, width + PAD2, height + PAD2);
	emu_texture = SDL_CreateTexture(emu_renderer, SDL_PIXELFORMAT_RGB888, SDL_TEXTUREACCESS_STATIC, width, height);
	if(emu_texture == NULL || SDL_SetTextureBlendMode(emu_texture, SDL_BLENDMODE_NONE))
		return system_error("SDL_SetTextureBlendMode", SDL_GetError());
	if(SDL_UpdateTexture(emu_texture, NULL, uxn_screen.pixels, sizeof(Uint32)) != 0)
		return system_error("SDL_UpdateTexture", SDL_GetError());
	emu_viewport.x = PAD;
	emu_viewport.y = PAD;
	emu_viewport.w = uxn_screen.width;
	emu_viewport.h = uxn_screen.height;
	set_window_size(emu_window, (width + PAD2) * zoom, (height + PAD2) * zoom);
	return 1;
}

static void
emu_redraw(Uxn *u)
{
	screen_redraw(u);
	if(SDL_UpdateTexture(emu_texture, NULL, uxn_screen.pixels, uxn_screen.width * sizeof(Uint32)) != 0)
		system_error("SDL_UpdateTexture", SDL_GetError());
	SDL_RenderClear(emu_renderer);
	SDL_RenderCopy(emu_renderer, emu_texture, NULL, &emu_viewport);
	SDL_RenderPresent(emu_renderer);
}

static int
emu_init(Uxn *u)
{
	SDL_AudioSpec as;
	SDL_zero(as);
	as.freq = SAMPLE_FREQUENCY;
	as.format = AUDIO_S16SYS;
	as.channels = 2;
	as.callback = audio_handler;
	as.samples = AUDIO_BUFSIZE;
	as.userdata = u;
	if(SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_JOYSTICK) < 0)
		return system_error("sdl", SDL_GetError());
	audio_id = SDL_OpenAudioDevice(NULL, 0, &as, NULL, 0);
	if(!audio_id)
		system_error("sdl_audio", SDL_GetError());
	if(SDL_NumJoysticks() > 0 && SDL_JoystickOpen(0) == NULL)
		system_error("sdl_joystick", SDL_GetError());
	stdin_event = SDL_RegisterEvents(1);
	audio0_event = SDL_RegisterEvents(POLYPHONY);
	SDL_DetachThread(stdin_thread = SDL_CreateThread(stdin_handler, "stdin", NULL));
	SDL_StartTextInput();
	SDL_ShowCursor(SDL_DISABLE);
	SDL_EventState(SDL_DROPFILE, SDL_ENABLE);
	SDL_SetRenderDrawColor(emu_renderer, 0x00, 0x00, 0x00, 0xff);
	ms_interval = SDL_GetPerformanceFrequency() / 1000;
	deadline_interval = ms_interval * TIMEOUT_MS;
	exec_deadline = SDL_GetPerformanceCounter() + deadline_interval;
	screen_resize(WIDTH, HEIGHT);
	SDL_PauseAudioDevice(audio_id, 1);
	return 1;
}

static void
emu_restart(Uxn *u, char *rom, int soft)
{
	screen_resize(WIDTH, HEIGHT);
	screen_fill(uxn_screen.bg, 0);
	screen_fill(uxn_screen.fg, 0);
	system_reboot(u, rom, soft);
	SDL_SetWindowTitle(emu_window, boot_rom);
}

static void
capture_screen(void)
{
	const Uint32 format = SDL_PIXELFORMAT_RGB24;
#if SDL_BYTEORDER == SDL_BIG_ENDIAN
	/* SDL_PIXELFORMAT_RGB24 */
	Uint32 Rmask = 0x000000FF;
	Uint32 Gmask = 0x0000FF00;
	Uint32 Bmask = 0x00FF0000;
#else
	/* SDL_PIXELFORMAT_BGR24 */
	Uint32 Rmask = 0x00FF0000;
	Uint32 Gmask = 0x0000FF00;
	Uint32 Bmask = 0x000000FF;
#endif
	time_t t = time(NULL);
	char fname[64];
	int w, h;
	SDL_Surface *surface;
	SDL_GetRendererOutputSize(emu_renderer, &w, &h);
	if((surface = SDL_CreateRGBSurface(0, w, h, 24, Rmask, Gmask, Bmask, 0)) == NULL)
		return;
	SDL_RenderReadPixels(emu_renderer, NULL, format, surface->pixels, surface->pitch);
	strftime(fname, sizeof(fname), "screenshot-%Y%m%d-%H%M%S.bmp", localtime(&t));
	if(SDL_SaveBMP(surface, fname) == 0) {
		fprintf(stderr, "Saved %s\n", fname);
		fflush(stderr);
	}
	SDL_FreeSurface(surface);
}

static Uint8
get_button(SDL_Event *event)
{
	switch(event->key.keysym.sym) {
	case SDLK_LCTRL: return 0x01;
	case SDLK_LALT: return 0x02;
	case SDLK_LSHIFT: return 0x04;
	case SDLK_HOME: return 0x08;
	case SDLK_UP: return 0x10;
	case SDLK_DOWN: return 0x20;
	case SDLK_LEFT: return 0x40;
	case SDLK_RIGHT: return 0x80;
	}
	return 0x00;
}

static Uint8
get_button_joystick(SDL_Event *event)
{
	return 0x01 << (event->jbutton.button & 0x3);
}

static Uint8
get_vector_joystick(SDL_Event *event)
{
	if(event->jaxis.value < -3200)
		return 1;
	if(event->jaxis.value > 3200)
		return 2;
	return 0;
}

static Uint8
get_key(SDL_Event *event)
{
	int sym = event->key.keysym.sym;
	SDL_Keymod mods = SDL_GetModState();
	if(sym < 0x20 || sym == SDLK_DELETE)
		return sym;
	if(mods & KMOD_CTRL) {
		if(sym < SDLK_a)
			return sym;
		else if(sym <= SDLK_z)
			return sym - (mods & KMOD_SHIFT) * 0x20;
	}
	return 0x00;
}

static int
handle_events(Uxn *u)
{
	SDL_Event event;
	while(SDL_PollEvent(&event)) {
		/* Window */
		if(event.type == SDL_QUIT)
			return 0;
		else if(event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_EXPOSED)
			emu_redraw(u);
		else if(event.type == SDL_DROPFILE) {
			emu_restart(u, event.drop.file, 0);
			SDL_free(event.drop.file);
		}
		/* Mouse */
		else if(event.type == SDL_MOUSEMOTION)
			mouse_pos(u, &u->dev[0x90], clamp(event.motion.x - PAD, 0, uxn_screen.width - 1), clamp(event.motion.y - PAD, 0, uxn_screen.height - 1));
		else if(event.type == SDL_MOUSEBUTTONUP)
			mouse_up(u, &u->dev[0x90], SDL_BUTTON(event.button.button));
		else if(event.type == SDL_MOUSEBUTTONDOWN)
			mouse_down(u, &u->dev[0x90], SDL_BUTTON(event.button.button));
		else if(event.type == SDL_MOUSEWHEEL)
			mouse_scroll(u, &u->dev[0x90], event.wheel.x, event.wheel.y);
		/* Controller */
		else if(event.type == SDL_TEXTINPUT) {
			char *c;
			for(c = event.text.text; *c; c++)
				controller_key(u, &u->dev[0x80], *c);
		} else if(event.type == SDL_KEYDOWN) {
			int ksym;
			if(get_key(&event))
				controller_key(u, &u->dev[0x80], get_key(&event));
			else if(get_button(&event))
				controller_down(u, &u->dev[0x80], get_button(&event));
			else if(event.key.keysym.sym == SDLK_F1)
				set_zoom(zoom == 3 ? 1 : zoom + 1, 1);
			else if(event.key.keysym.sym == SDLK_F2)
				set_debugger(u, !u->dev[0x0e]);
			else if(event.key.keysym.sym == SDLK_F3)
				capture_screen();
			else if(event.key.keysym.sym == SDLK_F4)
				emu_restart(u, boot_rom, 0);
			else if(event.key.keysym.sym == SDLK_F5)
				emu_restart(u, boot_rom, 1);
			else if(event.key.keysym.sym == SDLK_F11)
				set_fullscreen(!fullscreen, 1);
			else if(event.key.keysym.sym == SDLK_F12)
				set_borderless(!borderless);
			ksym = event.key.keysym.sym;
			if(SDL_PeepEvents(&event, 1, SDL_PEEKEVENT, SDL_KEYUP, SDL_KEYUP) == 1 && ksym == event.key.keysym.sym)
				return 1;
		} else if(event.type == SDL_KEYUP)
			controller_up(u, &u->dev[0x80], get_button(&event));
		else if(event.type == SDL_JOYAXISMOTION) {
			Uint8 vec = get_vector_joystick(&event);
			if(!vec)
				controller_up(u, &u->dev[0x80], (3 << (!event.jaxis.axis * 2)) << 4);
			else
				controller_down(u, &u->dev[0x80], (1 << ((vec + !event.jaxis.axis * 2) - 1)) << 4);
		} else if(event.type == SDL_JOYBUTTONDOWN)
			controller_down(u, &u->dev[0x80], get_button_joystick(&event));
		else if(event.type == SDL_JOYBUTTONUP)
			controller_up(u, &u->dev[0x80], get_button_joystick(&event));
		else if(event.type == SDL_JOYHATMOTION) {
			/* NOTE: Assuming there is only one joyhat in the controller */
			switch(event.jhat.value) {
			case SDL_HAT_UP: controller_down(u, &u->dev[0x80], 0x10); break;
			case SDL_HAT_DOWN: controller_down(u, &u->dev[0x80], 0x20); break;
			case SDL_HAT_LEFT: controller_down(u, &u->dev[0x80], 0x40); break;
			case SDL_HAT_RIGHT: controller_down(u, &u->dev[0x80], 0x80); break;
			case SDL_HAT_LEFTDOWN: controller_down(u, &u->dev[0x80], 0x40 | 0x20); break;
			case SDL_HAT_LEFTUP: controller_down(u, &u->dev[0x80], 0x40 | 0x10); break;
			case SDL_HAT_RIGHTDOWN: controller_down(u, &u->dev[0x80], 0x80 | 0x20); break;
			case SDL_HAT_RIGHTUP: controller_down(u, &u->dev[0x80], 0x80 | 0x10); break;
			case SDL_HAT_CENTERED: controller_up(u, &u->dev[0x80], 0x10 | 0x20 | 0x40 | 0x80); break;
			}
		}
		/* Console */
		else if(event.type == stdin_event)
			console_input(u, event.cbutton.button, CONSOLE_STD);
	}
	return 1;
}

static int
emu_run(Uxn *u, char *rom)
{
	Uint64 next_refresh = 0;
	Uint64 frame_interval = SDL_GetPerformanceFrequency() / 60;
	Uint8 *vector_addr = &u->dev[0x20];
	Uint32 window_flags = SDL_WINDOW_SHOWN | SDL_WINDOW_ALLOW_HIGHDPI;
	window_created = 1;
	if(fullscreen)
		window_flags = window_flags | SDL_WINDOW_FULLSCREEN_DESKTOP;
	emu_window = SDL_CreateWindow(rom,
		SDL_WINDOWPOS_UNDEFINED,
		SDL_WINDOWPOS_UNDEFINED,
		(uxn_screen.width + PAD2) * zoom,
		(uxn_screen.height + PAD2) * zoom,
		window_flags);
	if(emu_window == NULL)
		return system_error("sdl_window", SDL_GetError());
	emu_renderer = SDL_CreateRenderer(emu_window, -1, SDL_RENDERER_ACCELERATED);
	if(emu_renderer == NULL)
		return system_error("sdl_renderer", SDL_GetError());
	emu_resize(uxn_screen.width, uxn_screen.height);
	/* game loop */
	for(;;) {
		Uint16 screen_vector;
		Uint64 now = SDL_GetPerformanceCounter();
		/* .System/halt */
		if(u->dev[0x0f])
			return system_error("Run", "Ended.");
		exec_deadline = now + deadline_interval;
		if(!handle_events(u))
			return 0;
		screen_vector = PEEK2(vector_addr);
		if(now >= next_refresh) {
			now = SDL_GetPerformanceCounter();
			next_refresh = now + frame_interval;
			uxn_eval(u, screen_vector);
			if(uxn_screen.x2)
				emu_redraw(u);
		}
		if(screen_vector || uxn_screen.x2) {
			Uint64 delay_ms = (next_refresh - now) / ms_interval;
			if(delay_ms > 0) SDL_Delay(delay_ms);
		} else
			SDL_WaitEvent(NULL);
	}
}

static int
emu_end(Uxn *u)
{
	SDL_CloseAudioDevice(audio_id);
#ifdef _WIN32
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	TerminateThread((HANDLE)SDL_GetThreadID(stdin_thread), 0);
#elif !defined(__APPLE__)
	close(0); /* make stdin thread exit */
#endif
	SDL_Quit();
	free(u->ram);
	return u->dev[0x0f] & 0x7f;
}

int
main(int argc, char **argv)
{
	int i = 1;
	Uint8 *ram;
	char *rom;
	Uxn u = {0};
	Uint8 dev[0x100] = {0};
	Uxn u_audio = {0};
	u.dev = dev;
	u_audio.dev = dev;
	/* flags */
	if(argc > 1 && argv[i][0] == '-') {
		if(!strcmp(argv[i], "-v"))
			return system_error("Uxnemu - Varvara Emulator(GUI)", "18 Mar 2024.");
		else if(!strcmp(argv[i], "-2x"))
			set_zoom(2, 0);
		else if(!strcmp(argv[i], "-3x"))
			set_zoom(3, 0);
		else if(strcmp(argv[i], "-f") == 0)
			set_fullscreen(1, 0);
		i++;
	}
	/* start */
	rom = i == argc ? "boot.rom" : argv[i++];
	ram = (Uint8 *)calloc(0x10000 * RAM_PAGES, sizeof(Uint8));
	if(!system_init(&u, ram, rom) || !system_init(&u_audio, ram, rom))
		return system_error("usage:", "uxnemu [-v | -f | -2x | -3x] file.rom [args...]");
	if(!emu_init(&u_audio))
		return system_error("Init", "Failed to initialize varvara.");
	/* loop */
	u.dev[0x17] = argc - i;
	if(uxn_eval(&u, PAGE_PROGRAM)) {
		console_listen(&u, i, argc, argv);
		emu_run(&u, boot_rom);
	}
	return emu_end(&u);
}
