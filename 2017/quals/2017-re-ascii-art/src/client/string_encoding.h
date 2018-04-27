/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#include <functional>
#include <string>
#include <vector>

class StringEncoder {
public:
	explicit StringEncoder();
	void encode_string(std::string &input_string);
	void decode_string(std::string &input_string);

	static void xor_with_length(std::string &input_string);
	static void xor_with_first_char(std::string &input_string);
	static void reverse_string(std::string &input_string);
	static void invert_pairs(std::string &input_string);
	static void xor_with_last_char(std::string &input_string);
	static void encode_hex(const std::string& input_string, std::string& output_string);
	static void decode_hex(const std::string& input_string, std::string& output_string);

private:
	// a vector of string encoding functions.
	std::vector< std::function<void(std::string&)> > call_vector;
};