// Copyright 2023 Google LLC
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

// ---------------------------------------------------------------------------------------
// * * * Compile-time String Obfuscation using C++ templates * * *
//
// The idea here is to use templates (which are resolved at compile time) to obfuscate
// constant strings in the code. The encryption (i.e., string obfuscation) part
// constitutes only of constexpr expressions, so everything is resolved at compile time
// and only the obfuscated string is added directly to the binary.
//
// The decryption (i.e., string deobfuscation) part, is dynamic and its algorithm is
// added to the binary.
//
// To obfuscate a string simply use the `OBF` macro:
//
//      printf("%s", OBF("Obfuscate me!"));
//
// The actual string obfuscation algorithm can be anything, but for this case we use a
// stream cipher with a key derived from a Linear Congruential Generator (LCG). We do
// not care about strong cryptographic properties as the decryption needs to take place
// inside the binary.
//
//
// NOTE: An alternative -and more modern- way to obfuscate the strings is to use an LLVM
//       pass, but we're old school :$
//
// Author: Kyriakos Ispoglou (ispo)
// ---------------------------------------------------------------------------------------
#ifndef __STROBF_H__
#define __STROBF_H__

#include <string>
#include <array>
#include <cstdarg>


// We need a pseudo-random value to obfuscate strings.
// This value comes from the Makefile.
#ifndef PRNG_SEED
    #error "PRNG_SEED is not defined!"
#endif


/** Recursive template to generate the i-th number of an LCG. */
template <uint32_t i, uint32_t seed>
struct LinearCongruentialGenerator {
    // See: https://en.wikipedia.org/wiki/Linear_congruential_generator
    static constexpr uint32_t a = 8121;    // Multiplier.
    static constexpr uint32_t m = 134456;  // Modulus.
    static constexpr uint32_t c = 28411;   // Increment.
    
    static constexpr uint32_t val = (a * LinearCongruentialGenerator<i - 1, seed>::val + c) % m;
};


/** Specialized template for the base case (the 1st element in the LCG). */
template <uint32_t seed>
struct LinearCongruentialGenerator<0, seed> {
    // Initialize it to a random number from Makefile.
    static constexpr uint32_t val = seed + PRNG_SEED;
};


/** Gets the LSByte from the i-th number of the LCG sequence. */
template <uint8_t i, uint32_t seed>
struct PseudoRandomByte {
    static constexpr uint8_t val = LinearCongruentialGenerator<i, seed>::val & 0xFF;
};


/** Main string obfuscator class.  */
template <size_t len, int seed>
struct ObfuscateString {
    const std::array<uint8_t, len> keystream;  // +1 for the NULL byte.
    std::array<uint8_t, len> encrypted;  // The encrypted string.


    /** Compile time encryption. */   
    constexpr uint8_t XorEncr(char p, size_t i) const {
        return p ^ keystream[i] & 0xFF;
    }

    /** Runtime decryption. */
    char XorDecr(uint8_t c, size_t i) const {
        return c ^ keystream[i] & 0xFF;
    }

    /** ctor. Initialize PRNG and encrypt string. */
    template <size_t ... Indices>
    constexpr __attribute__((always_inline))
    ObfuscateString(const char* str, std::index_sequence<Indices... >) :
        keystream{PseudoRandomByte<Indices, seed>::val ...},
        encrypted{XorEncr(str[Indices], Indices) ...} {}

    /** Runtime decryption (this function goes into the compiled binary). */
    __attribute__((always_inline)) const char *decrypt(void) {
        for (size_t i=0; i<len - 1; ++i) {
            encrypted[i] = XorDecr(encrypted[i], i);
        }
        
        encrypted[len - 1] = '\0';  // Don't forget the trailing NULL byte.

        return (const char*)encrypted.data();
    }
};


/**
 * The final obfuscation MACRO.
 *   
 * NOTE: Needs to be a lambda, with a `constexpr`, o/w encryption appear in the binary.
 */
#define OBF(str) []{                                 \
        constexpr ObfuscateString<sizeof(str), 0> os(\
            str,                                     \
            std::make_index_sequence<sizeof(str)>());\
        return os;                                   \
    }().decrypt()


#endif  // __STROBF_H__

