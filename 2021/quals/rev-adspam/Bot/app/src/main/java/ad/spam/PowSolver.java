// Copyright 2021 Google LLC
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

package ad.spam;

import android.util.Base64;

import java.math.BigInteger;

public class PowSolver {

    private final String VERSION = "s";
    private final BigInteger ONE = BigInteger.ONE;
    private final BigInteger TWO = BigInteger.valueOf(2);
    private final BigInteger FOUR = BigInteger.valueOf(4);
    private final BigInteger MODULUS = TWO.pow(1279).subtract(ONE);

    private byte[] decodeBase64(String enc) {
        return Base64.decode(enc, Base64.DEFAULT);
    }

    private String encodeBase64(byte[] s) {
        return Base64.encodeToString(s, Base64.NO_WRAP);
    }

    private BigInteger slothRoot(BigInteger x, BigInteger diff, BigInteger p) {
        BigInteger exp = p.add(ONE).divide(FOUR);
        for (long i = 0; i < diff.longValue(); ++i) {
            x = x.modPow(exp, p).xor(ONE);
        }
        return x;
    }

    private BigInteger decodeNumber(String enc) {
        return new BigInteger(decodeBase64(enc));
    }

    private String encodeNumber(BigInteger num) {
        int size = (num.bitLength() / 24) * 3 + 3;
        byte[] num_ba = num.toByteArray();
        byte[] solution = new byte[size];
        for (int i = num_ba.length - 1, j = size - 1; i >= 0 && j >= 0; --i, --j) {
            solution[j] = num_ba[i];
        }
        return encodeBase64(solution);
    }

    public String solveChallenge(String chal) {
        String[] parts = chal.split("\\.");
        if (!parts[0].equals(VERSION)) {
            throw new IllegalArgumentException("Unknown challenge version");
        }
        BigInteger diff = decodeNumber(parts[1]);
        BigInteger x = decodeNumber(parts[2]);
        BigInteger y = slothRoot(x, diff, MODULUS);
        return VERSION + "." + encodeNumber(y);
    }
}
