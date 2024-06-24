/*
Copyright (c) 2021 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

typedef signed int Sint32;

#define AUDIO_VERSION 1

#define AUDIO_BUFSIZE 256.0f
#define SAMPLE_FREQUENCY 44100.0f
#define POLYPHONY 4

Uint8 audio_get_vu(int instance);
Uint16 audio_get_position(int instance);
int audio_render(int instance, Sint16 *sample, Sint16 *end);
void audio_start(int instance, Uint8 *d, Uxn *u);
void audio_finished_handler(int instance);
void audio_handler(void *ctx, Uint8 *out_stream, int len);
Uint8 audio_dei(int instance, Uint8 *d, Uint8 port);
