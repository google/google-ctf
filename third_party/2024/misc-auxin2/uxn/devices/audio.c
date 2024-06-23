#include "../uxn.h"
#include "audio.h"
#include <stdbool.h>
#include <string.h>

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick, Bad Diode

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

#define SOUND_TIMER (AUDIO_BUFSIZE / SAMPLE_FREQUENCY * 1000.0f)
#define XFADE_SAMPLES 100
#define INTERPOL_METHOD 1

typedef enum EnvStage {
	ENV_ATTACK = (1 << 0),
	ENV_DECAY = (1 << 1),
	ENV_SUSTAIN = (1 << 2),
	ENV_RELEASE = (1 << 3),
} EnvStage;

typedef struct Envelope {
	float a;
	float d;
	float s;
	float r;
	float vol;
	EnvStage stage;
} Envelope;

typedef struct Sample {
	Uint8 *data;
	float len;
	float pos;
	float inc;
	float loop;
	Uint8 pitch;
	Envelope env;
} Sample;

typedef struct AudioChannel {
	Sample sample;
	Sample next_sample;
	bool xfade;
	float duration;
	float vol_l;
	float vol_r;
} AudioChannel;

AudioChannel channel[POLYPHONY];

/* clang-format off */

const float tuning[109] = {
        0.00058853f, 0.00062352f, 0.00066060f, 0.00069988f, 0.00074150f,
        0.00078559f, 0.00083230f, 0.00088179f, 0.00093423f, 0.00098978f,
        0.00104863f, 0.00111099f, 0.00117705f, 0.00124704f, 0.00132120f,
        0.00139976f, 0.00148299f, 0.00157118f, 0.00166460f, 0.00176359f,
        0.00186845f, 0.00197956f, 0.00209727f, 0.00222198f, 0.00235410f,
        0.00249409f, 0.00264239f, 0.00279952f, 0.00296599f, 0.00314235f,
        0.00332921f, 0.00352717f, 0.00373691f, 0.00395912f, 0.00419454f,
        0.00444396f, 0.00470821f, 0.00498817f, 0.00528479f, 0.00559904f,
        0.00593197f, 0.00628471f, 0.00665841f, 0.00705434f, 0.00747382f,
        0.00791823f, 0.00838908f, 0.00888792f, 0.00941642f, 0.00997635f,
        0.01056957f, 0.01119807f, 0.01186395f, 0.01256941f, 0.01331683f,
        0.01410869f, 0.01494763f, 0.01583647f, 0.01677815f, 0.01777583f,
        0.01883284f, 0.01995270f, 0.02113915f, 0.02239615f, 0.02372789f,
        0.02513882f, 0.02663366f, 0.02821738f, 0.02989527f, 0.03167293f,
        0.03355631f, 0.03555167f, 0.03766568f, 0.03990540f, 0.04227830f,
        0.04479229f, 0.04745578f, 0.05027765f, 0.05326731f, 0.05643475f,
        0.05979054f, 0.06334587f, 0.06711261f, 0.07110333f, 0.07533136f,
        0.07981079f, 0.08455659f, 0.08958459f, 0.09491156f, 0.10055530f,
        0.10653463f, 0.11286951f, 0.11958108f, 0.12669174f, 0.13422522f,
        0.14220667f, 0.15066272f, 0.15962159f, 0.16911318f, 0.17916918f,
        0.18982313f, 0.20111060f, 0.21306926f, 0.22573902f, 0.23916216f,
        0.25338348f, 0.26845044f, 0.28441334f, 0.30132544f,
};

/* clang-format on */

void
env_on(Envelope *env)
{
	env->stage = ENV_ATTACK;
	env->vol = 0.0f;
	if(env->a > 0) {
		env->a = (SOUND_TIMER / AUDIO_BUFSIZE) / env->a;
	} else if(env->stage == ENV_ATTACK) {
		env->stage = ENV_DECAY;
		env->vol = 1.0f;
	}
	if(env->d < 10.0f) {
		env->d = 10.0f;
	}
	env->d = (SOUND_TIMER / AUDIO_BUFSIZE) / env->d;
	if(env->r < 10.0f) {
		env->r = 10.0f;
	}
	env->r = (SOUND_TIMER / AUDIO_BUFSIZE) / env->r;
}

void
env_off(Envelope *env)
{
	env->stage = ENV_RELEASE;
}

void
note_on(AudioChannel *channel, float duration, Uint8 *data, Uint16 len, Uint8 vol, Uint8 attack, Uint8 decay, Uint8 sustain, Uint8 release, Uint8 pitch, bool loop)
{
	channel->duration = duration;
	channel->vol_l = (vol >> 4) / 15.0f;
	channel->vol_r = (vol & 0xf) / 15.0f;

	Sample sample = {0};
	sample.data = data;
	sample.len = len;
	sample.pos = 0;
	sample.env.a = attack * 64.0f;
	sample.env.d = decay * 64.0f;
	sample.env.s = sustain / 16.0f;
	sample.env.r = release * 64.0f;
	if(loop) {
		sample.loop = len;
	} else {
		sample.loop = 0;
	}
	env_on(&sample.env);
	float sample_rate = 44100 / 261.60;
	if(len <= 256) {
		sample_rate = len;
	}
	const float *inc = &tuning[pitch - 20];
	sample.inc = *(inc)*sample_rate;

	channel->next_sample = sample;
	channel->xfade = true;
}

void
note_off(AudioChannel *channel, float duration)
{
	channel->duration = duration;
	env_off(&channel->sample.env);
}

void
env_advance(Envelope *env)
{
	switch(env->stage) {
	case ENV_ATTACK: {
		env->vol += env->a;
		if(env->vol >= 1.0f) {
			env->stage = ENV_DECAY;
			env->vol = 1.0f;
		}
	} break;
	case ENV_DECAY: {
		env->vol -= env->d;
		if(env->vol <= env->s || env->d <= 0) {
			env->stage = ENV_SUSTAIN;
			env->vol = env->s;
		}
	} break;
	case ENV_SUSTAIN: {
		env->vol = env->s;
	} break;
	case ENV_RELEASE: {
		if(env->vol <= 0 || env->r <= 0) {
			env->vol = 0;
		} else {
			env->vol -= env->r;
		}
	} break;
	}
}

float
interpolate_sample(Uint8 *data, Uint16 len, float pos)
{
#if INTERPOL_METHOD == 0
	return data[(int)pos];

#elif INTERPOL_METHOD == 1
	float x = pos;
	int x0 = (int)x;
	int x1 = (x0 + 1);
	float y0 = data[x0];
	float y1 = data[x1 % len];
	x = x - x0;
	float y = y0 + x * (y1 - y0);
	return y;

#elif INTERPOL_METHOD == 2
	float x = pos;
	int x0 = x - 1;
	int x1 = x;
	int x2 = x + 1;
	int x3 = x + 2;
	float y0 = data[x0 % len];
	float y1 = data[x1];
	float y2 = data[x2 % len];
	float y3 = data[x3 % len];
	x = x - x1;
	float c0 = y1;
	float c1 = 0.5f * (y2 - y0);
	float c2 = y0 - 2.5f * y1 + 2.f * y2 - 0.5f * y3;
	float c3 = 1.5f * (y1 - y2) + 0.5f * (y3 - y0);
	return ((c3 * x + c2) * x + c1) * x + c0;
#endif
}

Sint16
next_sample(Sample *sample)
{
	if(sample->pos >= sample->len) {
		if(sample->loop == 0) {
			sample->data = 0;
			return 0;
		}
		while(sample->pos >= sample->len) {
			sample->pos -= sample->loop;
		}
	}

	float val = interpolate_sample(sample->data, sample->len, sample->pos);
	val *= sample->env.vol;
	Sint8 next = (Sint8)0x80 ^ (Uint8)val;

	sample->pos += sample->inc;
	env_advance(&sample->env);
	return next;
}

void
audio_handler(void *ctx, Uint8 *out_stream, int len)
{
	Sint16 *stream = (Sint16 *)out_stream;
	memset(stream, 0x00, len);

	int n;
	for(n = 0; n < POLYPHONY; n++) {
		Uint8 device = (3 + n) << 4;
		Uxn *u = (Uxn *)ctx;
		Uint8 *addr = &u->dev[device];
		if(channel[n].duration <= 0 && PEEK2(addr)) {
			uxn_eval(u, PEEK2(addr));
		}
		channel[n].duration -= SOUND_TIMER;

		int x = 0;
		if(channel[n].xfade) {
			float delta = 1.0f / (XFADE_SAMPLES * 2);
			while(x < XFADE_SAMPLES * 2) {
				float alpha = x * delta;
				float beta = 1.0f - alpha;
				Sint16 next_a = next_sample(&channel[n].next_sample);
				Sint16 next_b = 0;
				if(channel[n].sample.data != 0) {
					next_b = next_sample(&channel[n].sample);
				}
				Sint16 next = alpha * next_a + beta * next_b;
				stream[x++] += next * channel[n].vol_l;
				stream[x++] += next * channel[n].vol_r;
			}
			channel[n].sample = channel[n].next_sample;
			channel[n].xfade = false;
		}
		Sample *sample = &channel[n].sample;
		while(x < len / 2) {
			if(sample->data == 0) {
				break;
			}
			Sint16 next = next_sample(sample);
			stream[x++] += next * channel[n].vol_l;
			stream[x++] += next * channel[n].vol_r;
		}
	}
	int i;
	for(i = 0; i < len / 2; i++) {
		stream[i] <<= 6;
	}
}

float
calc_duration(Uint16 len, Uint8 pitch)
{
	float scale = tuning[pitch - 20] / tuning[0x3c - 20];
	return len / (scale * 44.1f);
}

void
audio_start(int idx, Uint8 *d, Uxn *u)
{
	Uint16 dur = PEEK2(d + 0x5);
	Uint8 off = d[0xf] == 0x00;
	Uint16 len = PEEK2(d + 0xa);
	Uint8 pitch = d[0xf] & 0x7f;
	if(pitch < 20) {
		pitch = 20;
	}
	float duration = dur > 0 ? dur : calc_duration(len, pitch);

	if(!off) {
		Uint16 addr = PEEK2(d + 0xc);
		Uint8 *data = &u->ram[addr];
		Uint8 volume = d[0xe];
		bool loop = !(d[0xf] & 0x80);
		Uint16 adsr = PEEK2(d + 0x8);
		Uint8 attack = (adsr >> 12) & 0xF;
		Uint8 decay = (adsr >> 8) & 0xF;
		Uint8 sustain = (adsr >> 4) & 0xF;
		Uint8 release = (adsr >> 0) & 0xF;
		note_on(&channel[idx], duration, data, len, volume, attack, decay, sustain, release, pitch, loop);
	} else {
		note_off(&channel[idx], duration);
	}
}

Uint8
audio_get_vu(int instance)
{
	return channel[instance].sample.env.vol * 255.0f;
}

Uint16
audio_get_position(int instance)
{
	return channel[instance].sample.pos;
}

Uint8
audio_dei(int instance, Uint8 *d, Uint8 port)
{
	switch(port) {
	case 0x2: return audio_get_position(instance) >> 8;
	case 0x3: return audio_get_position(instance);
	case 0x4: return audio_get_vu(instance);
	}
	return d[port];
}
