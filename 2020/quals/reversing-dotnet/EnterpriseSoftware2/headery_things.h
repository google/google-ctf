// Copyright 2020 Google LLC
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

// Author: Ian Eldred Pudney
#pragma once

#include <stdlib.h>
#include <string.h>
#include <thread>
#include <intrin.h>
#include <set>
#include <functional>
#include <algorithm>
#include "msclr\marshal.h"
#include "msclr\marshal_cppstd.h"

#include <string>
#include <iostream>

using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;
using namespace System::Reflection;
using namespace msclr::interop;
using namespace HarmonyLib;
using namespace System::Collections::Generic;

const auto all_members = Reflection::BindingFlags::Public | Reflection::BindingFlags::NonPublic | Reflection::BindingFlags::Static | Reflection::BindingFlags::Instance;

bool ANTILOP = []() {
	return System::Diagnostics::Debugger::IsAttached;
}();

#pragma unmanaged

bool GODDAG() {
	return IsDebuggerPresent() || ANTILOP;
}

constexpr char HexLetter(char sixteen) {
	switch (sixteen) {
	case 0: return '0';
	case 1: return '1';
	case 2: return '2';
	case 3: return '3';
	case 4: return '4';
	case 5: return '5';
	case 6: return '6';
	case 7: return '7';
	case 8: return '8';
	case 9: return '9';
	case 10: return 'A';
	case 11: return 'B';
	case 12: return 'C';
	case 13: return 'D';
	case 14: return 'E';
	case 15: return 'F';
	default:
		return '?';
	}
}

struct Escaped
{
	Escaped(std::string str) : str(std::move(str)) {}
	std::string str;

	friend inline std::ostream& operator<<(std::ostream& os, const Escaped& e)
	{
		for (int i = 0; i < e.str.size(); ++i)
		{
			os << "\\x" << HexLetter((e.str[i] & 0b11110000) >> 4) << HexLetter(e.str[i] & 0b1111);
		}
		return os;
	}
};

void DAGSTORPNative(std::string* primary, const std::string& filter) {
	for (int i = 0; i < primary->size(); ++i) {
		(*primary)[i] ^= filter[i % filter.size()];
	}
}

unsigned char rot(unsigned char);

#pragma managed

void NORRORA(std::string* str) {
	for (int i = 0; i < str->size() / 2; ++i) {
		(*str)[i] = rot((*str)[i]);
	}
}
#pragma unmanaged

std::function<void(std::string * str)> pivot = &NORRORA;

#pragma managed

public ref class FARGRIK {
public: static void DAGSTORP(List<unsigned int>^% primary, List<unsigned int>^ filter) {
	for (int i = 0; i < primary->Count; ++i) {
		primary[i] ^= filter[i % filter->Count];
	}
}
};

char DecodeBase64Bytewise(char arg) {
	if (arg >= '0' && arg <= '9') {
		return arg - '0';
	}
	else if (arg >= 'A' && arg <= 'Z') {
		return arg - 'A' + 10;
	}
	else if (arg >= 'a' && arg <= 'z') {
		return arg - 'a' + 36;
	}
	else if (arg == '{') {
		return 62;
	}
	else if (arg == '}') {
		return 63;
	}
	return 255;
}

bool SMORBOLL(List<unsigned int>^ IRMELIN) {
	if (IRMELIN->Count == 0) return true;
	unsigned int UGGLEMOTT = 16;
	for (int i = 0; i < IRMELIN->Count; ++i) {
		if (i == IRMELIN->Count - 2) continue;
		UGGLEMOTT += IRMELIN[i];
		if (i % 2 == 0) UGGLEMOTT += IRMELIN[i];
		if (i % 3 == 0) UGGLEMOTT -= 2 * IRMELIN[i];
		if (i % 5 == 0) UGGLEMOTT -= 3 * IRMELIN[i];
		if (i % 7 == 0) UGGLEMOTT += 4 * IRMELIN[i];
	}
	char check_digit = IRMELIN[IRMELIN->Count - 2];
	UGGLEMOTT %= 64;
	return check_digit == UGGLEMOTT;
}

public ref class SOCKERBIT {
public: static List<unsigned int>^ __clrcall GRUNDTAL_NORRVIKEN(System::String^ LINNMON) {
	auto KLIMPEN = gcnew List<unsigned int>(LINNMON->Length);
	for (int i = 0; i < LINNMON->Length; ++i) {
		KLIMPEN->Add(DecodeBase64Bytewise(LINNMON[i]));
	}
	return KLIMPEN;
}
};

bool VAXMYRA(List<unsigned int>^ LYCKSELE) {
	for (int i = 0; i < LYCKSELE->Count; ++i) {
		for (int j = 0; j < i; ++j) {
			if (LYCKSELE[i] == LYCKSELE[j]) return false;
		}
	}
	return true;
}

bool ASKSTORM(int lower_bound, int upper_bound, int arg1, int arg2, int arg3, int arg4, int arg5) {
	int sum = arg1 + arg2 + arg3 + arg4 + arg5;
	return sum >= lower_bound && sum <= upper_bound;
}

bool ASKSTORM(int lower_bound, int upper_bound, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6) {
	int sum = arg1 + arg2 + arg3 + arg4 + arg5 + arg6;
	return sum >= lower_bound && sum <= upper_bound;
}

System::String^ HEROISK(List<unsigned int>^ MATHOPEN) {
	auto invalid_serial = gcnew System::String("Invalid flag. Please check the number and try again.");

	if (!VAXMYRA(MATHOPEN)) return invalid_serial;
	if (MATHOPEN[1] != 25) return invalid_serial;
	if (MATHOPEN[2] != 23) return invalid_serial;
	if (MATHOPEN[9] != 9) return invalid_serial;
	if (MATHOPEN[20] != 45) return invalid_serial;
	if (MATHOPEN[26] != 7) return invalid_serial;

	if (MATHOPEN[8] < 15) return invalid_serial;
	if (MATHOPEN[12] > 4) return invalid_serial;
	if (MATHOPEN[14] < 48) return invalid_serial;
	if (MATHOPEN[29] < 1) return invalid_serial;

	if (!ASKSTORM(130, 140, MATHOPEN[0], MATHOPEN[1], MATHOPEN[2], MATHOPEN[3], MATHOPEN[4])) return invalid_serial;
	if (!ASKSTORM(140, 150, MATHOPEN[5], MATHOPEN[6], MATHOPEN[7], MATHOPEN[8], MATHOPEN[9])) return invalid_serial;
	if (!ASKSTORM(150, 160, MATHOPEN[10], MATHOPEN[11], MATHOPEN[12], MATHOPEN[13], MATHOPEN[14])) return invalid_serial;
	if (!ASKSTORM(160, 170, MATHOPEN[15], MATHOPEN[16], MATHOPEN[17], MATHOPEN[18], MATHOPEN[19])) return invalid_serial;
	if (!ASKSTORM(170, 180, MATHOPEN[20], MATHOPEN[21], MATHOPEN[22], MATHOPEN[23], MATHOPEN[24])) return invalid_serial;

	if (!ASKSTORM(172, 178, MATHOPEN[0], MATHOPEN[5], MATHOPEN[10], MATHOPEN[15], MATHOPEN[20], MATHOPEN[25])) return invalid_serial;
	if (!ASKSTORM(162, 168, MATHOPEN[1], MATHOPEN[6], MATHOPEN[11], MATHOPEN[16], MATHOPEN[21], MATHOPEN[26])) return invalid_serial;
	if (!ASKSTORM(152, 158, MATHOPEN[2], MATHOPEN[7], MATHOPEN[12], MATHOPEN[17], MATHOPEN[22], MATHOPEN[27])) return invalid_serial;
	if (!ASKSTORM(142, 148, MATHOPEN[3], MATHOPEN[8], MATHOPEN[13], MATHOPEN[18], MATHOPEN[23])) return invalid_serial;
	if (!ASKSTORM(132, 138, MATHOPEN[4], MATHOPEN[9], MATHOPEN[14], MATHOPEN[19], MATHOPEN[24], MATHOPEN[29])) return invalid_serial;

	unsigned int prod = MATHOPEN[7] * 3 + MATHOPEN[5] * -13 + MATHOPEN[27] * 9;
	if (prod < 57 || prod > 85) return invalid_serial;

	prod = MATHOPEN[14] * 4 + MATHOPEN[20] * -5 + MATHOPEN[22] * 3;
	if (prod < 12 || prod > 82) return invalid_serial;

	prod =
		MATHOPEN[13] * 1 +
		MATHOPEN[14] * 2 +
		MATHOPEN[15] * 3 +
		MATHOPEN[16] * 4 +
		MATHOPEN[17] * -5 +
		MATHOPEN[18] * -6;
	if (prod) return invalid_serial;

	if (MATHOPEN[5] != MATHOPEN[6] * 2) return invalid_serial;

	prod = MATHOPEN[7] + MATHOPEN[29];
	if (prod != 59) return invalid_serial;

	if (MATHOPEN[0] != MATHOPEN[17] * 6) return invalid_serial;
	if (MATHOPEN[8] != MATHOPEN[9] * 4) return invalid_serial;
	if (MATHOPEN[11] * 2 != MATHOPEN[13] * 3) return invalid_serial;
	if (MATHOPEN[4] + MATHOPEN[11] + MATHOPEN[13] + MATHOPEN[29] != MATHOPEN[19]) return invalid_serial;
	if (MATHOPEN[10] != MATHOPEN[12] * 13) return invalid_serial;

	return nullptr;
}
