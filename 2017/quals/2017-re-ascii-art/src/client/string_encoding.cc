// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



#include "string_encoding.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>

StringEncoder::StringEncoder() {
	call_vector.push_back(StringEncoder::xor_with_length);
	call_vector.push_back(StringEncoder::xor_with_first_char);
	call_vector.push_back(StringEncoder::reverse_string);
	call_vector.push_back(StringEncoder::invert_pairs);
	call_vector.push_back(StringEncoder::xor_with_last_char);
}

void StringEncoder::encode_string(std::string &input_string) {
	ssize_t func_index = input_string.length();
	func_index = func_index % 5;
	size_t nb_decode = 0;

	while(nb_decode < 5) {
		call_vector[func_index](input_string);
		nb_decode += 1;
		func_index = (func_index + 1) % 5;
	}

	std::string hex_encoded;
	StringEncoder::encode_hex(input_string, hex_encoded);
	input_string.assign(hex_encoded);
}

void StringEncoder::decode_string(std::string &input_string) {
	std::string hex_decoded;
	StringEncoder::decode_hex(input_string, hex_decoded);
	input_string.assign(hex_decoded);

	ssize_t func_index = input_string.length();
	func_index = (func_index % 5) - 1;
	size_t nb_decode = 0;

	while(nb_decode < 5){
		if(func_index == -1)
			func_index = 4;
		call_vector[func_index](input_string);

		nb_decode += 1;
		func_index -= 1;
	}
}

void StringEncoder::xor_with_length(std::string &input_string) {
	char xor_key = input_string.length() % 0xff;
	for(size_t i = 0; i < input_string.length(); i++)
		input_string[i] = (input_string[i] ^ xor_key);
}

void StringEncoder::xor_with_first_char(std::string &input_string) {
	if (input_string.length() == 0)
		return;

	char xor_key = input_string[0];
	for(size_t i = 1; i < input_string.length(); i++)
		input_string[i] = input_string[i] ^ xor_key;
}

void StringEncoder::xor_with_last_char(std::string &input_string) {
	if (input_string.length() == 0)
		return;

	char xor_key = input_string.back();
	for(size_t i = 0; i < input_string.length() - 1; i++)
		input_string[i] = input_string[i] ^ xor_key;
}

void StringEncoder::reverse_string(std::string &input_string) {
	std::string original_string(input_string);
	for(size_t i = 0; i < input_string.length(); i++)
		input_string[i] = original_string[original_string.length() - 1 - i];
}

void StringEncoder::invert_pairs(std::string &input_string) {
	size_t i = 0;
	while(i < input_string.length()) {
		if (i < input_string.length() - 1) {
			char tmp = input_string[i];
			input_string[i] = input_string[i + 1];
			input_string[i+1] = tmp;
		}
		i = i + 2;
	}
}

void StringEncoder::encode_hex(const std::string& input_string, std::string& output_string) {
	std::ostringstream output_stream;
	for (size_t i = 0; i < input_string.length(); ++i)
	    output_stream << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << (int)input_string[i];
	output_string.assign(output_stream.str());
}

void StringEncoder::decode_hex(const std::string& input_string, std::string& output_string) {
    if ((input_string.length() % 2) != 0) {
        return;
    }

    output_string = "";
    size_t cnt = input_string.length() / 2;

    for (size_t i = 0; i < cnt; ++i) {
        size_t s = 0;
        std::stringstream ss;
        ss << std::hex << input_string.substr(i * 2, 2);
        ss >> s;

        output_string.push_back(static_cast<unsigned char>(s));
    }
}