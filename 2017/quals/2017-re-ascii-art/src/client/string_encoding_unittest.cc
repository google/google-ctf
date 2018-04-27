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



#include <string>

#include "gtest/gtest.h"
#include "string_encoding.h"

TEST(StringEncodingTest, XorWithLength) {
	std::string my_test("abc");
    StringEncoder::xor_with_length(my_test);
    EXPECT_STREQ("\x62\x61\x60", my_test.c_str());
    StringEncoder::xor_with_length(my_test);
    EXPECT_TRUE("abc" == my_test);
}

TEST(StringEncodingTest, XorWithFirstChar) {
	std::string my_test("abc");
	StringEncoder::xor_with_first_char(my_test);
	EXPECT_TRUE("\x61\x3\x2" == my_test);
	StringEncoder::xor_with_first_char(my_test);
	EXPECT_TRUE("abc" == my_test);
}

TEST(StringEncodingTest, XorWithLastChar) {
	std::string my_test("abcd");
	StringEncoder::xor_with_last_char(my_test);
	EXPECT_TRUE("\x5\x6\x7\x64" == my_test);
	StringEncoder::xor_with_last_char(my_test);
	EXPECT_TRUE("abcd" == my_test);
}

TEST(StringEncodingTest, ReverseString) {
	std::string my_string_to_reverse("abc");
	StringEncoder::reverse_string(my_string_to_reverse);
	EXPECT_TRUE("cba" == my_string_to_reverse);
	StringEncoder::reverse_string(my_string_to_reverse);
	EXPECT_TRUE("abc" == my_string_to_reverse);
}

TEST(StringEncodingTest, InvertPairs) {
	std::string inverted_pairs("abcd");
	StringEncoder::invert_pairs(inverted_pairs);
	EXPECT_TRUE("badc" == inverted_pairs);
	StringEncoder::invert_pairs(inverted_pairs);
	EXPECT_TRUE("abcd" == inverted_pairs);

	std::string uneven_pairs("abc");
	StringEncoder::invert_pairs(uneven_pairs);
	EXPECT_TRUE("bac" == uneven_pairs);
	StringEncoder::invert_pairs(uneven_pairs);
	EXPECT_TRUE("abc" == uneven_pairs);
}

TEST(StringEncodingTest, EncodeString) {
	StringEncoder encoder;
	std::string to_encode("HelloWorld");
	encoder.encode_string(to_encode);
	encoder.decode_string(to_encode);
	EXPECT_STREQ("HelloWorld", to_encode.c_str());

	std::string second = "aabb";
	encoder.encode_string(second);
	encoder.decode_string(second);
	EXPECT_STREQ("aabb", second.c_str());

	to_encode = "a";
	std::string reference = "a";
	for(size_t i = 0; i < 26; i++) {
		reference += ('a' + i);
		to_encode = reference;
		encoder.encode_string(to_encode);
		encoder.decode_string(to_encode);
		EXPECT_STREQ(reference.c_str(), to_encode.c_str());
	}
}

TEST(StringEncodingTest, HexEncode) {
	StringEncoder encoder;
	std::string output;
	encoder.encode_hex("foobar", output);
	EXPECT_TRUE("666F6F626172" == output);
}

TEST(StringEncodingTest, HexDecode) {
	std::string hex_decoded;
	StringEncoder::decode_hex("666F6F626172", hex_decoded);
	EXPECT_STREQ("foobar", hex_decoded.c_str());
}