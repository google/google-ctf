// Copyright 2021 Google LLC
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

// Author: Ian Eldred Pudney

/*
This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.
The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED
ECB-AES128
----------
  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710
  key:
    2b7e151628aed2a6abf7158809cf4f3c
  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97
    f5d3d58503b9699de785895a96fdbaaf
    43b1cd7f598ece23881b00e3ed030688
    7b0c785e27e8ad3f8223207104725dd4
NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.
*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> // CBC mode, for memset
#include "aes.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif

// jcallan@github points out that declaring Multiply as a function
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];



// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
volatile uint64_t sbox_xor_filter = SBOX_XOR_FILTER;

static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  SBOX_XOR_FILTER_0 ^ 0x63, SBOX_XOR_FILTER_1 ^ 0x7c, SBOX_XOR_FILTER_2 ^ 0x77, SBOX_XOR_FILTER_3 ^ 0x7b, SBOX_XOR_FILTER_4 ^ 0xf2, SBOX_XOR_FILTER_5 ^ 0x6b, SBOX_XOR_FILTER_6 ^ 0x6f, SBOX_XOR_FILTER_7 ^ 0xc5, SBOX_XOR_FILTER_0 ^ 0x30, SBOX_XOR_FILTER_1 ^ 0x01, SBOX_XOR_FILTER_2 ^ 0x67, SBOX_XOR_FILTER_3 ^ 0x2b, SBOX_XOR_FILTER_4 ^ 0xfe, SBOX_XOR_FILTER_5 ^ 0xd7, SBOX_XOR_FILTER_6 ^ 0xab, SBOX_XOR_FILTER_7 ^ 0x76,
  SBOX_XOR_FILTER_0 ^ 0xca, SBOX_XOR_FILTER_1 ^ 0x82, SBOX_XOR_FILTER_2 ^ 0xc9, SBOX_XOR_FILTER_3 ^ 0x7d, SBOX_XOR_FILTER_4 ^ 0xfa, SBOX_XOR_FILTER_5 ^ 0x59, SBOX_XOR_FILTER_6 ^ 0x47, SBOX_XOR_FILTER_7 ^ 0xf0, SBOX_XOR_FILTER_0 ^ 0xad, SBOX_XOR_FILTER_1 ^ 0xd4, SBOX_XOR_FILTER_2 ^ 0xa2, SBOX_XOR_FILTER_3 ^ 0xaf, SBOX_XOR_FILTER_4 ^ 0x9c, SBOX_XOR_FILTER_5 ^ 0xa4, SBOX_XOR_FILTER_6 ^ 0x72, SBOX_XOR_FILTER_7 ^ 0xc0,
  SBOX_XOR_FILTER_0 ^ 0xb7, SBOX_XOR_FILTER_1 ^ 0xfd, SBOX_XOR_FILTER_2 ^ 0x93, SBOX_XOR_FILTER_3 ^ 0x26, SBOX_XOR_FILTER_4 ^ 0x36, SBOX_XOR_FILTER_5 ^ 0x3f, SBOX_XOR_FILTER_6 ^ 0xf7, SBOX_XOR_FILTER_7 ^ 0xcc, SBOX_XOR_FILTER_0 ^ 0x34, SBOX_XOR_FILTER_1 ^ 0xa5, SBOX_XOR_FILTER_2 ^ 0xe5, SBOX_XOR_FILTER_3 ^ 0xf1, SBOX_XOR_FILTER_4 ^ 0x71, SBOX_XOR_FILTER_5 ^ 0xd8, SBOX_XOR_FILTER_6 ^ 0x31, SBOX_XOR_FILTER_7 ^ 0x15,
  SBOX_XOR_FILTER_0 ^ 0x04, SBOX_XOR_FILTER_1 ^ 0xc7, SBOX_XOR_FILTER_2 ^ 0x23, SBOX_XOR_FILTER_3 ^ 0xc3, SBOX_XOR_FILTER_4 ^ 0x18, SBOX_XOR_FILTER_5 ^ 0x96, SBOX_XOR_FILTER_6 ^ 0x05, SBOX_XOR_FILTER_7 ^ 0x9a, SBOX_XOR_FILTER_0 ^ 0x07, SBOX_XOR_FILTER_1 ^ 0x12, SBOX_XOR_FILTER_2 ^ 0x80, SBOX_XOR_FILTER_3 ^ 0xe2, SBOX_XOR_FILTER_4 ^ 0xeb, SBOX_XOR_FILTER_5 ^ 0x27, SBOX_XOR_FILTER_6 ^ 0xb2, SBOX_XOR_FILTER_7 ^ 0x75,
  SBOX_XOR_FILTER_0 ^ 0x09, SBOX_XOR_FILTER_1 ^ 0x83, SBOX_XOR_FILTER_2 ^ 0x2c, SBOX_XOR_FILTER_3 ^ 0x1a, SBOX_XOR_FILTER_4 ^ 0x1b, SBOX_XOR_FILTER_5 ^ 0x6e, SBOX_XOR_FILTER_6 ^ 0x5a, SBOX_XOR_FILTER_7 ^ 0xa0, SBOX_XOR_FILTER_0 ^ 0x52, SBOX_XOR_FILTER_1 ^ 0x3b, SBOX_XOR_FILTER_2 ^ 0xd6, SBOX_XOR_FILTER_3 ^ 0xb3, SBOX_XOR_FILTER_4 ^ 0x29, SBOX_XOR_FILTER_5 ^ 0xe3, SBOX_XOR_FILTER_6 ^ 0x2f, SBOX_XOR_FILTER_7 ^ 0x84,
  SBOX_XOR_FILTER_0 ^ 0x53, SBOX_XOR_FILTER_1 ^ 0xd1, SBOX_XOR_FILTER_2 ^ 0x00, SBOX_XOR_FILTER_3 ^ 0xed, SBOX_XOR_FILTER_4 ^ 0x20, SBOX_XOR_FILTER_5 ^ 0xfc, SBOX_XOR_FILTER_6 ^ 0xb1, SBOX_XOR_FILTER_7 ^ 0x5b, SBOX_XOR_FILTER_0 ^ 0x6a, SBOX_XOR_FILTER_1 ^ 0xcb, SBOX_XOR_FILTER_2 ^ 0xbe, SBOX_XOR_FILTER_3 ^ 0x39, SBOX_XOR_FILTER_4 ^ 0x4a, SBOX_XOR_FILTER_5 ^ 0x4c, SBOX_XOR_FILTER_6 ^ 0x58, SBOX_XOR_FILTER_7 ^ 0xcf,
  SBOX_XOR_FILTER_0 ^ 0xd0, SBOX_XOR_FILTER_1 ^ 0xef, SBOX_XOR_FILTER_2 ^ 0xaa, SBOX_XOR_FILTER_3 ^ 0xfb, SBOX_XOR_FILTER_4 ^ 0x43, SBOX_XOR_FILTER_5 ^ 0x4d, SBOX_XOR_FILTER_6 ^ 0x33, SBOX_XOR_FILTER_7 ^ 0x85, SBOX_XOR_FILTER_0 ^ 0x45, SBOX_XOR_FILTER_1 ^ 0xf9, SBOX_XOR_FILTER_2 ^ 0x02, SBOX_XOR_FILTER_3 ^ 0x7f, SBOX_XOR_FILTER_4 ^ 0x50, SBOX_XOR_FILTER_5 ^ 0x3c, SBOX_XOR_FILTER_6 ^ 0x9f, SBOX_XOR_FILTER_7 ^ 0xa8,
  SBOX_XOR_FILTER_0 ^ 0x51, SBOX_XOR_FILTER_1 ^ 0xa3, SBOX_XOR_FILTER_2 ^ 0x40, SBOX_XOR_FILTER_3 ^ 0x8f, SBOX_XOR_FILTER_4 ^ 0x92, SBOX_XOR_FILTER_5 ^ 0x9d, SBOX_XOR_FILTER_6 ^ 0x38, SBOX_XOR_FILTER_7 ^ 0xf5, SBOX_XOR_FILTER_0 ^ 0xbc, SBOX_XOR_FILTER_1 ^ 0xb6, SBOX_XOR_FILTER_2 ^ 0xda, SBOX_XOR_FILTER_3 ^ 0x21, SBOX_XOR_FILTER_4 ^ 0x10, SBOX_XOR_FILTER_5 ^ 0xff, SBOX_XOR_FILTER_6 ^ 0xf3, SBOX_XOR_FILTER_7 ^ 0xd2,
  SBOX_XOR_FILTER_0 ^ 0xcd, SBOX_XOR_FILTER_1 ^ 0x0c, SBOX_XOR_FILTER_2 ^ 0x13, SBOX_XOR_FILTER_3 ^ 0xec, SBOX_XOR_FILTER_4 ^ 0x5f, SBOX_XOR_FILTER_5 ^ 0x97, SBOX_XOR_FILTER_6 ^ 0x44, SBOX_XOR_FILTER_7 ^ 0x17, SBOX_XOR_FILTER_0 ^ 0xc4, SBOX_XOR_FILTER_1 ^ 0xa7, SBOX_XOR_FILTER_2 ^ 0x7e, SBOX_XOR_FILTER_3 ^ 0x3d, SBOX_XOR_FILTER_4 ^ 0x64, SBOX_XOR_FILTER_5 ^ 0x5d, SBOX_XOR_FILTER_6 ^ 0x19, SBOX_XOR_FILTER_7 ^ 0x73,
  SBOX_XOR_FILTER_0 ^ 0x60, SBOX_XOR_FILTER_1 ^ 0x81, SBOX_XOR_FILTER_2 ^ 0x4f, SBOX_XOR_FILTER_3 ^ 0xdc, SBOX_XOR_FILTER_4 ^ 0x22, SBOX_XOR_FILTER_5 ^ 0x2a, SBOX_XOR_FILTER_6 ^ 0x90, SBOX_XOR_FILTER_7 ^ 0x88, SBOX_XOR_FILTER_0 ^ 0x46, SBOX_XOR_FILTER_1 ^ 0xee, SBOX_XOR_FILTER_2 ^ 0xb8, SBOX_XOR_FILTER_3 ^ 0x14, SBOX_XOR_FILTER_4 ^ 0xde, SBOX_XOR_FILTER_5 ^ 0x5e, SBOX_XOR_FILTER_6 ^ 0x0b, SBOX_XOR_FILTER_7 ^ 0xdb,
  SBOX_XOR_FILTER_0 ^ 0xe0, SBOX_XOR_FILTER_1 ^ 0x32, SBOX_XOR_FILTER_2 ^ 0x3a, SBOX_XOR_FILTER_3 ^ 0x0a, SBOX_XOR_FILTER_4 ^ 0x49, SBOX_XOR_FILTER_5 ^ 0x06, SBOX_XOR_FILTER_6 ^ 0x24, SBOX_XOR_FILTER_7 ^ 0x5c, SBOX_XOR_FILTER_0 ^ 0xc2, SBOX_XOR_FILTER_1 ^ 0xd3, SBOX_XOR_FILTER_2 ^ 0xac, SBOX_XOR_FILTER_3 ^ 0x62, SBOX_XOR_FILTER_4 ^ 0x91, SBOX_XOR_FILTER_5 ^ 0x95, SBOX_XOR_FILTER_6 ^ 0xe4, SBOX_XOR_FILTER_7 ^ 0x79,
  SBOX_XOR_FILTER_0 ^ 0xe7, SBOX_XOR_FILTER_1 ^ 0xc8, SBOX_XOR_FILTER_2 ^ 0x37, SBOX_XOR_FILTER_3 ^ 0x6d, SBOX_XOR_FILTER_4 ^ 0x8d, SBOX_XOR_FILTER_5 ^ 0xd5, SBOX_XOR_FILTER_6 ^ 0x4e, SBOX_XOR_FILTER_7 ^ 0xa9, SBOX_XOR_FILTER_0 ^ 0x6c, SBOX_XOR_FILTER_1 ^ 0x56, SBOX_XOR_FILTER_2 ^ 0xf4, SBOX_XOR_FILTER_3 ^ 0xea, SBOX_XOR_FILTER_4 ^ 0x65, SBOX_XOR_FILTER_5 ^ 0x7a, SBOX_XOR_FILTER_6 ^ 0xae, SBOX_XOR_FILTER_7 ^ 0x08,
  SBOX_XOR_FILTER_0 ^ 0xba, SBOX_XOR_FILTER_1 ^ 0x78, SBOX_XOR_FILTER_2 ^ 0x25, SBOX_XOR_FILTER_3 ^ 0x2e, SBOX_XOR_FILTER_4 ^ 0x1c, SBOX_XOR_FILTER_5 ^ 0xa6, SBOX_XOR_FILTER_6 ^ 0xb4, SBOX_XOR_FILTER_7 ^ 0xc6, SBOX_XOR_FILTER_0 ^ 0xe8, SBOX_XOR_FILTER_1 ^ 0xdd, SBOX_XOR_FILTER_2 ^ 0x74, SBOX_XOR_FILTER_3 ^ 0x1f, SBOX_XOR_FILTER_4 ^ 0x4b, SBOX_XOR_FILTER_5 ^ 0xbd, SBOX_XOR_FILTER_6 ^ 0x8b, SBOX_XOR_FILTER_7 ^ 0x8a,
  SBOX_XOR_FILTER_0 ^ 0x70, SBOX_XOR_FILTER_1 ^ 0x3e, SBOX_XOR_FILTER_2 ^ 0xb5, SBOX_XOR_FILTER_3 ^ 0x66, SBOX_XOR_FILTER_4 ^ 0x48, SBOX_XOR_FILTER_5 ^ 0x03, SBOX_XOR_FILTER_6 ^ 0xf6, SBOX_XOR_FILTER_7 ^ 0x0e, SBOX_XOR_FILTER_0 ^ 0x61, SBOX_XOR_FILTER_1 ^ 0x35, SBOX_XOR_FILTER_2 ^ 0x57, SBOX_XOR_FILTER_3 ^ 0xb9, SBOX_XOR_FILTER_4 ^ 0x86, SBOX_XOR_FILTER_5 ^ 0xc1, SBOX_XOR_FILTER_6 ^ 0x1d, SBOX_XOR_FILTER_7 ^ 0x9e,
  SBOX_XOR_FILTER_0 ^ 0xe1, SBOX_XOR_FILTER_1 ^ 0xf8, SBOX_XOR_FILTER_2 ^ 0x98, SBOX_XOR_FILTER_3 ^ 0x11, SBOX_XOR_FILTER_4 ^ 0x69, SBOX_XOR_FILTER_5 ^ 0xd9, SBOX_XOR_FILTER_6 ^ 0x8e, SBOX_XOR_FILTER_7 ^ 0x94, SBOX_XOR_FILTER_0 ^ 0x9b, SBOX_XOR_FILTER_1 ^ 0x1e, SBOX_XOR_FILTER_2 ^ 0x87, SBOX_XOR_FILTER_3 ^ 0xe9, SBOX_XOR_FILTER_4 ^ 0xce, SBOX_XOR_FILTER_5 ^ 0x55, SBOX_XOR_FILTER_6 ^ 0x28, SBOX_XOR_FILTER_7 ^ 0xdf,
  SBOX_XOR_FILTER_0 ^ 0x8c, SBOX_XOR_FILTER_1 ^ 0xa1, SBOX_XOR_FILTER_2 ^ 0x89, SBOX_XOR_FILTER_3 ^ 0x0d, SBOX_XOR_FILTER_4 ^ 0xbf, SBOX_XOR_FILTER_5 ^ 0xe6, SBOX_XOR_FILTER_6 ^ 0x42, SBOX_XOR_FILTER_7 ^ 0x68, SBOX_XOR_FILTER_0 ^ 0x41, SBOX_XOR_FILTER_1 ^ 0x99, SBOX_XOR_FILTER_2 ^ 0x2d, SBOX_XOR_FILTER_3 ^ 0x0f, SBOX_XOR_FILTER_4 ^ 0xb0, SBOX_XOR_FILTER_5 ^ 0x54, SBOX_XOR_FILTER_6 ^ 0xbb, SBOX_XOR_FILTER_7 ^ 0x16 };

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t rsbox[256] = {
  SBOX_XOR_FILTER_0 ^ 0x52, SBOX_XOR_FILTER_1 ^ 0x09, SBOX_XOR_FILTER_2 ^ 0x6a, SBOX_XOR_FILTER_3 ^ 0xd5, SBOX_XOR_FILTER_4 ^ 0x30, SBOX_XOR_FILTER_5 ^ 0x36, SBOX_XOR_FILTER_6 ^ 0xa5, SBOX_XOR_FILTER_7 ^ 0x38, SBOX_XOR_FILTER_0 ^ 0xbf, SBOX_XOR_FILTER_1 ^ 0x40, SBOX_XOR_FILTER_2 ^ 0xa3, SBOX_XOR_FILTER_3 ^ 0x9e, SBOX_XOR_FILTER_4 ^ 0x81, SBOX_XOR_FILTER_5 ^ 0xf3, SBOX_XOR_FILTER_6 ^ 0xd7, SBOX_XOR_FILTER_7 ^ 0xfb,
  SBOX_XOR_FILTER_0 ^ 0x7c, SBOX_XOR_FILTER_1 ^ 0xe3, SBOX_XOR_FILTER_2 ^ 0x39, SBOX_XOR_FILTER_3 ^ 0x82, SBOX_XOR_FILTER_4 ^ 0x9b, SBOX_XOR_FILTER_5 ^ 0x2f, SBOX_XOR_FILTER_6 ^ 0xff, SBOX_XOR_FILTER_7 ^ 0x87, SBOX_XOR_FILTER_0 ^ 0x34, SBOX_XOR_FILTER_1 ^ 0x8e, SBOX_XOR_FILTER_2 ^ 0x43, SBOX_XOR_FILTER_3 ^ 0x44, SBOX_XOR_FILTER_4 ^ 0xc4, SBOX_XOR_FILTER_5 ^ 0xde, SBOX_XOR_FILTER_6 ^ 0xe9, SBOX_XOR_FILTER_7 ^ 0xcb,
  SBOX_XOR_FILTER_0 ^ 0x54, SBOX_XOR_FILTER_1 ^ 0x7b, SBOX_XOR_FILTER_2 ^ 0x94, SBOX_XOR_FILTER_3 ^ 0x32, SBOX_XOR_FILTER_4 ^ 0xa6, SBOX_XOR_FILTER_5 ^ 0xc2, SBOX_XOR_FILTER_6 ^ 0x23, SBOX_XOR_FILTER_7 ^ 0x3d, SBOX_XOR_FILTER_0 ^ 0xee, SBOX_XOR_FILTER_1 ^ 0x4c, SBOX_XOR_FILTER_2 ^ 0x95, SBOX_XOR_FILTER_3 ^ 0x0b, SBOX_XOR_FILTER_4 ^ 0x42, SBOX_XOR_FILTER_5 ^ 0xfa, SBOX_XOR_FILTER_6 ^ 0xc3, SBOX_XOR_FILTER_7 ^ 0x4e,
  SBOX_XOR_FILTER_0 ^ 0x08, SBOX_XOR_FILTER_1 ^ 0x2e, SBOX_XOR_FILTER_2 ^ 0xa1, SBOX_XOR_FILTER_3 ^ 0x66, SBOX_XOR_FILTER_4 ^ 0x28, SBOX_XOR_FILTER_5 ^ 0xd9, SBOX_XOR_FILTER_6 ^ 0x24, SBOX_XOR_FILTER_7 ^ 0xb2, SBOX_XOR_FILTER_0 ^ 0x76, SBOX_XOR_FILTER_1 ^ 0x5b, SBOX_XOR_FILTER_2 ^ 0xa2, SBOX_XOR_FILTER_3 ^ 0x49, SBOX_XOR_FILTER_4 ^ 0x6d, SBOX_XOR_FILTER_5 ^ 0x8b, SBOX_XOR_FILTER_6 ^ 0xd1, SBOX_XOR_FILTER_7 ^ 0x25,
  SBOX_XOR_FILTER_0 ^ 0x72, SBOX_XOR_FILTER_1 ^ 0xf8, SBOX_XOR_FILTER_2 ^ 0xf6, SBOX_XOR_FILTER_3 ^ 0x64, SBOX_XOR_FILTER_4 ^ 0x86, SBOX_XOR_FILTER_5 ^ 0x68, SBOX_XOR_FILTER_6 ^ 0x98, SBOX_XOR_FILTER_7 ^ 0x16, SBOX_XOR_FILTER_0 ^ 0xd4, SBOX_XOR_FILTER_1 ^ 0xa4, SBOX_XOR_FILTER_2 ^ 0x5c, SBOX_XOR_FILTER_3 ^ 0xcc, SBOX_XOR_FILTER_4 ^ 0x5d, SBOX_XOR_FILTER_5 ^ 0x65, SBOX_XOR_FILTER_6 ^ 0xb6, SBOX_XOR_FILTER_7 ^ 0x92,
  SBOX_XOR_FILTER_0 ^ 0x6c, SBOX_XOR_FILTER_1 ^ 0x70, SBOX_XOR_FILTER_2 ^ 0x48, SBOX_XOR_FILTER_3 ^ 0x50, SBOX_XOR_FILTER_4 ^ 0xfd, SBOX_XOR_FILTER_5 ^ 0xed, SBOX_XOR_FILTER_6 ^ 0xb9, SBOX_XOR_FILTER_7 ^ 0xda, SBOX_XOR_FILTER_0 ^ 0x5e, SBOX_XOR_FILTER_1 ^ 0x15, SBOX_XOR_FILTER_2 ^ 0x46, SBOX_XOR_FILTER_3 ^ 0x57, SBOX_XOR_FILTER_4 ^ 0xa7, SBOX_XOR_FILTER_5 ^ 0x8d, SBOX_XOR_FILTER_6 ^ 0x9d, SBOX_XOR_FILTER_7 ^ 0x84,
  SBOX_XOR_FILTER_0 ^ 0x90, SBOX_XOR_FILTER_1 ^ 0xd8, SBOX_XOR_FILTER_2 ^ 0xab, SBOX_XOR_FILTER_3 ^ 0x00, SBOX_XOR_FILTER_4 ^ 0x8c, SBOX_XOR_FILTER_5 ^ 0xbc, SBOX_XOR_FILTER_6 ^ 0xd3, SBOX_XOR_FILTER_7 ^ 0x0a, SBOX_XOR_FILTER_0 ^ 0xf7, SBOX_XOR_FILTER_1 ^ 0xe4, SBOX_XOR_FILTER_2 ^ 0x58, SBOX_XOR_FILTER_3 ^ 0x05, SBOX_XOR_FILTER_4 ^ 0xb8, SBOX_XOR_FILTER_5 ^ 0xb3, SBOX_XOR_FILTER_6 ^ 0x45, SBOX_XOR_FILTER_7 ^ 0x06,
  SBOX_XOR_FILTER_0 ^ 0xd0, SBOX_XOR_FILTER_1 ^ 0x2c, SBOX_XOR_FILTER_2 ^ 0x1e, SBOX_XOR_FILTER_3 ^ 0x8f, SBOX_XOR_FILTER_4 ^ 0xca, SBOX_XOR_FILTER_5 ^ 0x3f, SBOX_XOR_FILTER_6 ^ 0x0f, SBOX_XOR_FILTER_7 ^ 0x02, SBOX_XOR_FILTER_0 ^ 0xc1, SBOX_XOR_FILTER_1 ^ 0xaf, SBOX_XOR_FILTER_2 ^ 0xbd, SBOX_XOR_FILTER_3 ^ 0x03, SBOX_XOR_FILTER_4 ^ 0x01, SBOX_XOR_FILTER_5 ^ 0x13, SBOX_XOR_FILTER_6 ^ 0x8a, SBOX_XOR_FILTER_7 ^ 0x6b,
  SBOX_XOR_FILTER_0 ^ 0x3a, SBOX_XOR_FILTER_1 ^ 0x91, SBOX_XOR_FILTER_2 ^ 0x11, SBOX_XOR_FILTER_3 ^ 0x41, SBOX_XOR_FILTER_4 ^ 0x4f, SBOX_XOR_FILTER_5 ^ 0x67, SBOX_XOR_FILTER_6 ^ 0xdc, SBOX_XOR_FILTER_7 ^ 0xea, SBOX_XOR_FILTER_0 ^ 0x97, SBOX_XOR_FILTER_1 ^ 0xf2, SBOX_XOR_FILTER_2 ^ 0xcf, SBOX_XOR_FILTER_3 ^ 0xce, SBOX_XOR_FILTER_4 ^ 0xf0, SBOX_XOR_FILTER_5 ^ 0xb4, SBOX_XOR_FILTER_6 ^ 0xe6, SBOX_XOR_FILTER_7 ^ 0x73,
  SBOX_XOR_FILTER_0 ^ 0x96, SBOX_XOR_FILTER_1 ^ 0xac, SBOX_XOR_FILTER_2 ^ 0x74, SBOX_XOR_FILTER_3 ^ 0x22, SBOX_XOR_FILTER_4 ^ 0xe7, SBOX_XOR_FILTER_5 ^ 0xad, SBOX_XOR_FILTER_6 ^ 0x35, SBOX_XOR_FILTER_7 ^ 0x85, SBOX_XOR_FILTER_0 ^ 0xe2, SBOX_XOR_FILTER_1 ^ 0xf9, SBOX_XOR_FILTER_2 ^ 0x37, SBOX_XOR_FILTER_3 ^ 0xe8, SBOX_XOR_FILTER_4 ^ 0x1c, SBOX_XOR_FILTER_5 ^ 0x75, SBOX_XOR_FILTER_6 ^ 0xdf, SBOX_XOR_FILTER_7 ^ 0x6e,
  SBOX_XOR_FILTER_0 ^ 0x47, SBOX_XOR_FILTER_1 ^ 0xf1, SBOX_XOR_FILTER_2 ^ 0x1a, SBOX_XOR_FILTER_3 ^ 0x71, SBOX_XOR_FILTER_4 ^ 0x1d, SBOX_XOR_FILTER_5 ^ 0x29, SBOX_XOR_FILTER_6 ^ 0xc5, SBOX_XOR_FILTER_7 ^ 0x89, SBOX_XOR_FILTER_0 ^ 0x6f, SBOX_XOR_FILTER_1 ^ 0xb7, SBOX_XOR_FILTER_2 ^ 0x62, SBOX_XOR_FILTER_3 ^ 0x0e, SBOX_XOR_FILTER_4 ^ 0xaa, SBOX_XOR_FILTER_5 ^ 0x18, SBOX_XOR_FILTER_6 ^ 0xbe, SBOX_XOR_FILTER_7 ^ 0x1b,
  SBOX_XOR_FILTER_0 ^ 0xfc, SBOX_XOR_FILTER_1 ^ 0x56, SBOX_XOR_FILTER_2 ^ 0x3e, SBOX_XOR_FILTER_3 ^ 0x4b, SBOX_XOR_FILTER_4 ^ 0xc6, SBOX_XOR_FILTER_5 ^ 0xd2, SBOX_XOR_FILTER_6 ^ 0x79, SBOX_XOR_FILTER_7 ^ 0x20, SBOX_XOR_FILTER_0 ^ 0x9a, SBOX_XOR_FILTER_1 ^ 0xdb, SBOX_XOR_FILTER_2 ^ 0xc0, SBOX_XOR_FILTER_3 ^ 0xfe, SBOX_XOR_FILTER_4 ^ 0x78, SBOX_XOR_FILTER_5 ^ 0xcd, SBOX_XOR_FILTER_6 ^ 0x5a, SBOX_XOR_FILTER_7 ^ 0xf4,
  SBOX_XOR_FILTER_0 ^ 0x1f, SBOX_XOR_FILTER_1 ^ 0xdd, SBOX_XOR_FILTER_2 ^ 0xa8, SBOX_XOR_FILTER_3 ^ 0x33, SBOX_XOR_FILTER_4 ^ 0x88, SBOX_XOR_FILTER_5 ^ 0x07, SBOX_XOR_FILTER_6 ^ 0xc7, SBOX_XOR_FILTER_7 ^ 0x31, SBOX_XOR_FILTER_0 ^ 0xb1, SBOX_XOR_FILTER_1 ^ 0x12, SBOX_XOR_FILTER_2 ^ 0x10, SBOX_XOR_FILTER_3 ^ 0x59, SBOX_XOR_FILTER_4 ^ 0x27, SBOX_XOR_FILTER_5 ^ 0x80, SBOX_XOR_FILTER_6 ^ 0xec, SBOX_XOR_FILTER_7 ^ 0x5f,
  SBOX_XOR_FILTER_0 ^ 0x60, SBOX_XOR_FILTER_1 ^ 0x51, SBOX_XOR_FILTER_2 ^ 0x7f, SBOX_XOR_FILTER_3 ^ 0xa9, SBOX_XOR_FILTER_4 ^ 0x19, SBOX_XOR_FILTER_5 ^ 0xb5, SBOX_XOR_FILTER_6 ^ 0x4a, SBOX_XOR_FILTER_7 ^ 0x0d, SBOX_XOR_FILTER_0 ^ 0x2d, SBOX_XOR_FILTER_1 ^ 0xe5, SBOX_XOR_FILTER_2 ^ 0x7a, SBOX_XOR_FILTER_3 ^ 0x9f, SBOX_XOR_FILTER_4 ^ 0x93, SBOX_XOR_FILTER_5 ^ 0xc9, SBOX_XOR_FILTER_6 ^ 0x9c, SBOX_XOR_FILTER_7 ^ 0xef,
  SBOX_XOR_FILTER_0 ^ 0xa0, SBOX_XOR_FILTER_1 ^ 0xe0, SBOX_XOR_FILTER_2 ^ 0x3b, SBOX_XOR_FILTER_3 ^ 0x4d, SBOX_XOR_FILTER_4 ^ 0xae, SBOX_XOR_FILTER_5 ^ 0x2a, SBOX_XOR_FILTER_6 ^ 0xf5, SBOX_XOR_FILTER_7 ^ 0xb0, SBOX_XOR_FILTER_0 ^ 0xc8, SBOX_XOR_FILTER_1 ^ 0xeb, SBOX_XOR_FILTER_2 ^ 0xbb, SBOX_XOR_FILTER_3 ^ 0x3c, SBOX_XOR_FILTER_4 ^ 0x83, SBOX_XOR_FILTER_5 ^ 0x53, SBOX_XOR_FILTER_6 ^ 0x99, SBOX_XOR_FILTER_7 ^ 0x61,
  SBOX_XOR_FILTER_0 ^ 0x17, SBOX_XOR_FILTER_1 ^ 0x2b, SBOX_XOR_FILTER_2 ^ 0x04, SBOX_XOR_FILTER_3 ^ 0x7e, SBOX_XOR_FILTER_4 ^ 0xba, SBOX_XOR_FILTER_5 ^ 0x77, SBOX_XOR_FILTER_6 ^ 0xd6, SBOX_XOR_FILTER_7 ^ 0x26, SBOX_XOR_FILTER_0 ^ 0xe1, SBOX_XOR_FILTER_1 ^ 0x69, SBOX_XOR_FILTER_2 ^ 0x14, SBOX_XOR_FILTER_3 ^ 0x63, SBOX_XOR_FILTER_4 ^ 0x55, SBOX_XOR_FILTER_5 ^ 0x21, SBOX_XOR_FILTER_6 ^ 0x0c, SBOX_XOR_FILTER_7 ^ 0x7d };
#endif

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  SBOX_XOR_FILTER_0 ^ 0x8d, SBOX_XOR_FILTER_1 ^ 0x01, SBOX_XOR_FILTER_2 ^ 0x02, SBOX_XOR_FILTER_3 ^ 0x04,
  SBOX_XOR_FILTER_4 ^ 0x08, SBOX_XOR_FILTER_5 ^ 0x10, SBOX_XOR_FILTER_6 ^ 0x20, SBOX_XOR_FILTER_7 ^ 0x40,
  SBOX_XOR_FILTER_0 ^ 0x80, SBOX_XOR_FILTER_1 ^ 0x1b, SBOX_XOR_FILTER_2 ^ 0x36
};

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 *
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed),
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num] ^ (SBOX_XOR_FILTER >> (8 * (num % 8)));
}

//#define getSBoxValue(num) (sbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num] ^ (SBOX_XOR_FILTER >> (8 * (num % 8)));
}

//#define getSBoxInvert(num) (rsbox[(num)])

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)


void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)





#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)



#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN];

  size_t i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {

      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        }
        ctx->Iv[bi] += 1;
        break;
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

#endif // #if defined(CTR) && (CTR == 1)
