// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdio.h>
#include <stdlib.h>
#include <printf.h>
#include <string.h>

#define CITY 4096
#define FLAG 6144

char buf[8192] = 

#include "code.h"

;

int reg[32];

#define CALC_WP \
	int width = info->width; \
	int prec = info->prec;

#define CALCDST \
	int* dst = NULL;\
	if (info->left) { dst = (int*)&buf[width]; } \
	else if (info->showsign) { dst = (int*)&buf[reg[width]]; } \
	else { dst = &reg[width]; } 

#define CALCSRC \
	int src = 0; \
	if (info->is_char) { src = *(int*)&buf[prec]; } \
	else if (info->is_short) { src = *(int*)&buf[reg[prec]]; } \
	else if (info->is_long_double) {  src = prec; } \
	else if (info->is_long) { src = reg[prec]; }

#define PROLOG CALC_WP CALCDST CALCSRC
#define SIMPLE(name, op) \
	int name(FILE *stream, const struct printf_info *info, const void *const *args) { \
		PROLOG; \
		op; \
		return 0; \
	}


SIMPLE(move, *dst = src);
SIMPLE(add, *dst += src);
SIMPLE(sub, *dst -= src);
SIMPLE(mul, *dst *= src);
SIMPLE(divi, *dst /= src);
SIMPLE(mod, *dst %= src);
SIMPLE(shl, *dst <<= src);
SIMPLE(shr, *dst >>= src);
SIMPLE(doxor, *dst ^= src);
SIMPLE(doand, *dst &= src);
SIMPLE(door, *dst |= src);

//SIMPLE(debug, printf("DEBUG: r%d = %d\n", prec, src));

int call(FILE *stream, const struct printf_info *info, const void *const *args) {
	CALC_WP;
	int cond = 1;
	if (info->left) {
		cond = reg[prec] < 0;
	}
	else if (info->showsign) {
		cond = reg[prec] > 0;
	}
	else if (info->pad == L'0') {
		cond = reg[prec] == 0;
	}
	else {
		cond = 1;
	}

	if (cond) {
		fprintf(stream, buf+width);
	}
	return 0; // Number of chars printed.
}

struct wind {
	int strength;
	const char* dir;
};
struct rain {
	const char* type;
	int count;
	const char* units;
};
struct temp {
	int count;
	const char* units;
};

int weather_wind(FILE *stream, const struct printf_info *info, const void *const *args) {
	const struct wind* wnd = *(const struct wind**)(args[0]);
	int len = fprintf(stream, "%dkm/h %s", wnd->strength, wnd->dir);
	return len;
}
int weather_rain(FILE *stream, const struct printf_info *info, const void *const *args) {
	const struct rain* rn = *(const struct rain**)(args[0]);
	if (rn->count == 0) {
		return fprintf(stream, "none");
	}
	else {
		return fprintf(stream, "%d%s of %s", rn->count, rn->units, rn->type);
	}
}
int weather_temp(FILE *stream, const struct printf_info *info, const void *const *args) {
	const struct temp* tp = *(const struct temp**)(args[0]);
	int len = fprintf(stream, "%d%s", tp->count, tp->units);
	return len;
}
int weather_flag(FILE *stream, const struct printf_info *info, const void *const *args) {
	const char* s = *(const char**)(args[0]);
	int len = fprintf(stream, buf, s);
	return len;
}

int ret0(const struct printf_info *info, size_t n, int *argtypes) {
	return 0; // No arguments.
}

int ret1(const struct printf_info *info, size_t n, int *argtypes) {
	argtypes[0] = PA_POINTER;
	return 1;
}

__attribute__((constructor)) void registerstuff() {
	register_printf_function('W', weather_wind, ret1);
	register_printf_function('P', weather_rain, ret1);
	register_printf_function('T', weather_temp, ret1);
	register_printf_function('F', weather_flag, ret1);

	register_printf_function('C', call, ret0);
	//register_printf_function('D', debug, ret0);
	register_printf_function('M', move, ret0);
	register_printf_function('S', add, ret0);
	register_printf_function('O', sub, ret0);
	register_printf_function('X', mul, ret0);
	register_printf_function('V', divi, ret0);
	register_printf_function('N', mod, ret0);
	register_printf_function('L', shl, ret0);
	register_printf_function('R', shr, ret0);
	register_printf_function('E', doxor, ret0);
	register_printf_function('I', doand, ret0);
	register_printf_function('U', door, ret0);
}

int main() {
	printf("Welcome to our global weather database!\n");
	printf("What city are you interested in?\n");
	scanf("%100s", buf+CITY);

	struct wind wnd;
	struct rain rn;
	struct temp tp;
	if (0 == strcmp("London", buf+CITY)) {
		wnd.strength = 5;
		wnd.dir = "W";

		rn.type = "rain";
		rn.count = 1337;
		rn.units = "mm";

		tp.count = 10;
		tp.units = "°C";
	}
	else if (0 == strcmp("Moscow", buf+CITY)) {
		wnd.strength = 7;
		wnd.dir = "N";

		rn.type = "snow";
		rn.count = 250;
		rn.units = "cm";

		tp.count = -30;
		tp.units = "°C";
	}
	else if (0 == strcmp("Miami", buf+CITY)) {
		wnd.strength = 1;
		wnd.dir = "NE";

		rn.type = "sweat";
		rn.count = 100;
		rn.units = "ml";

		tp.count = 31337;
		tp.units = "°F";
	}
	else {
		wnd.strength = 10;
		wnd.dir = "SW";

		rn.type = "nothing";
		rn.count = 0;
		rn.units = "";

		tp.count = 15;
		tp.units = "°C";
	}

	printf("Weather for today:\n");
	printf("Precipitation: %P\n", &rn);
	printf("Wind: %W\n", &wnd);
	printf("Temperature: %T\n", &tp);
	printf("Flag: %F\n", buf+FLAG);
}

