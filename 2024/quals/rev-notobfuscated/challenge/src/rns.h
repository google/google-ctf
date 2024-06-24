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

#pragma once

#include <iostream>
#include <array>
#include <cstdint>
#include <cstddef>
#include <cstdio>

#include "maths.h"

template <const std::size_t Mlen, const uint8_t Ms[Mlen]>
class RNS
{
private:
    uint16_t value;

    constexpr static uint16_t pack(const uint8_t x[Mlen])
    {
        uint16_t res = 0;
        for (std::size_t i = 0; i < Mlen; i++)
        {
            res <<= 4;
            res += x[i] & 0xF;
        }
        return res;
    }

    constexpr void unpack(uint8_t res[Mlen]) const
    {
        for (std::size_t i = 0; i < Mlen; i++)
        {
            res[Mlen - 1 - i] = (value >> (4 * i)) & 0xF;
        }
    }

public:
    void debug_print()
    {
        std::cout << *this;
    }

    constexpr RNS() : value(0) {}

    explicit constexpr RNS(const uint8_t x[Mlen]) : value(pack(x)) {}

    constexpr RNS(const uint16_t x)
    {
        uint8_t resvec[Mlen];
        for (std::size_t i = 0; i < Mlen; i++)
        {
            resvec[i] = x % Ms[i];
        }

        value = pack(resvec);
    }

    constexpr uint16_t decode() const
    {
        uint8_t valuevec[Mlen];
        unpack(valuevec);

        uint16_t solution = 0;
        for (std::size_t i = 0; i < Mlen; i++)
        {
            const uint16_t a_i = valuevec[i];
            const uint16_t M_i = Mmax / Ms[i];
            solution = (solution + a_i * M_i % Mmax * Minvs[i]) % Mmax;
        }
        return solution;
    }

    constexpr operator uint16_t() const
    {
        return value;
    }

    constexpr operator unsigned int() const
    {
        return value;
    }

    constexpr RNS &operator+=(const RNS &other)
    {
        uint8_t av[Mlen];
        uint8_t bv[Mlen];
        unpack(av);
        other.unpack(bv);

        for (std::size_t i = 0; i < Mlen; i++)
        {
            av[i] = (av[i] + bv[i]) % Ms[i];
        }
        value = pack(av);

        return *this;
    }

    constexpr RNS operator+(const RNS &other) const
    {
        RNS result(*this);
        result += other;
        return result;
    }

    constexpr RNS &operator=(const RNS &other)
    {
        value = other.value;
        return *this;
    }

    constexpr bool operator==(const RNS &other) const
    {
        uint8_t av[Mlen];
        uint8_t bv[Mlen];
        unpack(av);
        other.unpack(bv);
        for (std::size_t i = 0; i < Mlen; i++)
        {
            if(av[i] != bv[i]) {
                return false;
            }
        }
        return true;
    }

    constexpr bool operator!=(const RNS &other) const
    {
        return !(*this == other);
    }

    constexpr RNS &operator-=(const RNS &other)
    {
        uint8_t av[Mlen];
        uint8_t bv[Mlen];
        unpack(av);
        other.unpack(bv);

        for (std::size_t i = 0; i < Mlen; i++)
        {
            av[i] = (av[i] - bv[i] + Ms[i]) % Ms[i];
        }
        value = pack(av);

        return *this;
    }

    constexpr RNS operator-(const RNS &other) const
    {
        RNS result(*this);
        result -= other;
        return result;
    }

    constexpr RNS &operator*=(const RNS &other)
    {
        uint8_t av[Mlen];
        uint8_t bv[Mlen];
        unpack(av);
        other.unpack(bv);

        for (std::size_t i = 0; i < Mlen; i++)
        {
            av[i] = (av[i] * bv[i]) % Ms[i];
        }
        value = pack(av);

        return *this;
    }

    constexpr RNS operator*(const RNS &other) const
    {
        RNS result(*this);
        result *= other;
        return result;
    }

    constexpr RNS &operator^=(const RNS &b) const
    {
        *this = (*this) ^ b;
        return *this;
    }

    constexpr RNS operator^(const RNS &b) const
    {
        RNS result;
        result.value = xor_table[toindex()][b.toindex()];
        return result;
    }

    constexpr std::size_t toindex() const
    {
        std::size_t index = 0;
        uint8_t xvec[Mlen];
        unpack(xvec);
        for (std::size_t i = 0; i < Mlen; i++)
        {
            index += xvec[Mlen - 1 - i];
            if (i + 1 < Mlen)
            {
                index *= Ms[Mlen - 2 - i];
            }
        }
        return index;
    }

    // const static inline constexpr uint16_t Mlen = sizeof(Ms) / sizeof(Ms[0]);

    const static inline constexpr uint16_t Mmax = []() constexpr
    {
        uint16_t Mmax = 1;
        for (std::size_t i = 0; i < Mlen; i++)
        {
            Mmax *= Ms[i];
        }
        return Mmax;
    }();

    const static inline constexpr std::array<std::array<uint16_t, Mmax>, Mmax> xor_table = []() constexpr
    {
        std::array<std::array<uint16_t, Mmax>, Mmax> xor_table{};
        for (std::size_t a = 0; a < Mmax; a++)
        {
            for (std::size_t b = 0; b < Mmax; b++)
            {
                xor_table[RNS(a).toindex()][RNS(b).toindex()] = RNS(a ^ b).value;
            }
        }
        return xor_table;
    }();

    const static inline constexpr std::array<uint16_t, Mlen> Minvs = []() constexpr
    {
        std::array<uint16_t, Mlen> Minvs{};
        for (std::size_t i = 0; i < Mlen; i++)
        {
            Minvs[i] = mod_inv<int16_t>(Mmax / Ms[i], Ms[i]);
        }
        return Minvs;
    }();

    friend std::ostream &operator<<(std::ostream &os, const RNS<Mlen, Ms> &rns)
    {
        uint8_t xv[Mlen];
        rns.unpack(xv);

        os << "[";
        for (size_t i = 0; i < Mlen; i++)
        {
            os << (unsigned int)xv[i];
            if (i + 1 < Mlen)
            {
                os << ", ";
            }
        }
        os << "]";

        return os;
    }
};
