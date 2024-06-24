// Copyright 2024 Google LLC
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

#include <gtest/gtest.h>

#include "../rns.h"

constexpr uint8_t Ms[] = {4, 5, 13}; // 260
constexpr std::size_t Mlen = sizeof(Ms) / sizeof(Ms[0]);
typedef RNS<Mlen, Ms> rns;

TEST(RnsTest, EncodeDecode)
{
    const uint16_t int_val = 123;
    rns rns_val = int_val;
    EXPECT_EQ(rns_val.decode(), int_val);
}

TEST(RnsTest, Assignment)
{
    const uint16_t int_val = 123;
    rns rns_val1 = int_val;
    rns rns_val2 = rns_val1;

    EXPECT_EQ(rns_val1.decode(), int_val);
    EXPECT_EQ(rns_val2.decode(), int_val);
}

TEST(RnsTest, Addition)
{
    rns rns_val1 = 10;
    rns rns_val2 = 20;
    rns rns_val3 = rns_val1 + rns_val2;
    EXPECT_EQ(rns_val3.decode(), 10 + 20);
}
TEST(RnsTest, AdditionOverflow)
{
    rns rns_val1 = 100;
    rns rns_val2 = 200;
    rns rns_val3 = rns_val1 + rns_val2;
    EXPECT_EQ(rns_val3.decode(), (100 + 200) % rns::Mmax);
}
TEST(RnsTest, Subtraction)
{
    rns rns_val1 = 10;
    rns rns_val2 = 25;
    rns rns_val3 = rns_val2 - rns_val1;
    EXPECT_EQ(rns_val3.decode(), 25 - 10);
}
TEST(RnsTest, SubtractionUnderflow)
{
    rns rns_val1 = 10;
    rns rns_val2 = 25;
    rns rns_val3 = rns_val1 - rns_val2;
    EXPECT_EQ(rns_val3.decode(), (10 - 25 + rns::Mmax) % rns::Mmax);
}
TEST(RnsTest, Multiplication)
{
    rns rns_val1 = 10;
    rns rns_val2 = 20;
    rns rns_val3 = rns_val1 * rns_val2;
    EXPECT_EQ(rns_val3.decode(), 10 * 20);
}
TEST(RnsTest, MultiplicationOverflow)
{
    rns rns_val1 = 100;
    rns rns_val2 = 200;
    rns rns_val3 = rns_val1 * rns_val2;
    EXPECT_EQ(rns_val3.decode(), (100 * 200) % rns::Mmax);
}

TEST(RnsTest, Xor)
{
    for(size_t a = 0; a < 256; a++) {
        for(size_t b = 0; b < 256; b++) {
            rns rns_val1 = a;
            rns rns_val2 = b;
            rns rns_val3 = rns_val1 ^ rns_val2;
            EXPECT_EQ(rns_val3.decode(), a ^ b);
        }
    }
}
