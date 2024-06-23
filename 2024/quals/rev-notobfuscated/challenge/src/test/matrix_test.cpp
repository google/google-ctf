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
#include "../matrix.h"

constexpr uint8_t Ms[] = {4, 5, 13}; // 260
constexpr std::size_t Mlen = sizeof(Ms) / sizeof(Ms[0]);
typedef RNS<Mlen, Ms> rns;

typedef Matrix<4, 4, rns> matrix;

TEST(MatrixTest, Addition)
{
    matrix m1(rns((uint16_t)1));
    matrix m2(rns((uint16_t)2));
    matrix m3 = m1 + m2;
    auto m3_data = m3.get_data();

    for (size_t y = 0; y < 4; y++)
    {
        for (size_t x = 0; x < 4; x++)
        {
            EXPECT_EQ(m3_data[y][x], rns((uint16_t)3));
        }
    }
}

TEST(MatrixTest, MultiplicationIdentity)
{
    matrix m1(rns((uint16_t)5));
    matrix m2 = matrix::diagonal(rns((uint16_t)1));
    matrix m3 = m1 * m2;
    auto m3_data = m3.get_data();

    for (size_t y = 0; y < 4; y++)
    {
        for (size_t x = 0; x < 4; x++)
        {
            EXPECT_EQ(m3_data[y][x], rns((uint16_t)5));
        }
    }
}

TEST(MatrixTest, MultiplicationFull)
{
    matrix m1(rns((uint16_t)5));
    matrix m2(rns((uint16_t)3));
    matrix m3 = m1 * m2;
    auto m3_data = m3.get_data();

    for (size_t y = 0; y < 4; y++)
    {
        for (size_t x = 0; x < 4; x++)
        {
            EXPECT_EQ(m3_data[y][x].decode(), 60);
        }
    }
}
