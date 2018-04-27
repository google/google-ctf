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



package com.google.ctf.food;

public class ℝ {

    public static byte[] ℂ(final byte[] plaintext, byte[] key) {

        byte[] S = new byte[256];
        byte[] T = new byte[256];
        int i = 0, j = i, c = j;

        label_1: while (true) {
            label_2:
            {
                if (i == 256) {
                    break label_2;
                }

                S[i] = (byte) (i);
                T[i] = key[i % key.length];

                ++i;

                continue label_1;
            }

            break label_1;
        }

        i = i ^ i;
        label_3: while (true) {
            label_4:
            {
                if (i == 256) {
                    break label_4;
                }
                j = (j + S[i] + T[i]) & 0xFF;

                S[j] ^= S[i];
                S[i] ^= S[j];
                S[j] ^= S[i];

                ++i;
                continue label_3;
            }

            break  label_3;
        }

        final byte[] r = new byte[plaintext.length];
        i = i ^ i;
        j = j ^ j;

        label_5: while(true) {
            label_6:
            {
                if (c == plaintext.length) {
                    break label_6;
                }

                i = (i + 1) & 0xFF;
                j = (j + S[i]) & 0xFF;

                S[j] ^= S[i];
                S[i] ^= S[j];
                S[j] ^= S[i];

                r[c] = (byte) (plaintext[c] ^ S[(S[i] + S[j]) & 0xFF]);

                ++c;
                continue  label_5;
            }

            break  label_5;
        }

        return r;
    }
}