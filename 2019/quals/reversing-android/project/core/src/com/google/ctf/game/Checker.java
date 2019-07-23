// Copyright 2019 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.ctf.game;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Checker {

    private final static byte[] correctHash =
            {(byte)0x2e, (byte)0x32, (byte)0x5c, (byte)0x91, (byte)0xc9, (byte)0x14, (byte)0x78, (byte)0xb3,
                    (byte)0x5c, (byte)0x2e, (byte)0x0c, (byte)0xb6, (byte)0x5b, (byte)0x78, (byte)0x51, (byte)0xc6,
                    (byte)0xfa, (byte)0x98, (byte)0x85, (byte)0x5a, (byte)0x77, (byte)0xc3, (byte)0xbf, (byte)0xd3,
                    (byte)0xf0, (byte)0x08, (byte)0x40, (byte)0xbc, (byte)0x99, (byte)0xac, (byte)0xe2, (byte)0x6b};

    private final static byte[] initVector = {(byte)0xe2, (byte)0x1, (byte)0x9, (byte)0xe3, (byte)0xa4, (byte)0x68, (byte)0xcc, (byte)0xae,
            (byte)0x2a, (byte)0x8c, (byte)0x1, (byte)0xc6, (byte)0x5c, (byte)0xc8, (byte)0xe7, (byte)0x3e};

    /*
    private final static byte[] cipher = {(byte)0xfd, (byte)0xdf, (byte)0xbe, (byte)0x49, (byte)0xa4, (byte)0x39, (byte)0x68, (byte)0x31,
            (byte)0x3d, (byte)0xb7, (byte)0x35, (byte)0x46, (byte)0x45, (byte)0xef, (byte)0x26, (byte)0xc7,
            (byte)0x6b, (byte)0xe6, (byte)0xea, (byte)0x23, (byte)0xc0, (byte)0xc6, (byte)0x1e, (byte)0xfd,
            (byte)0xe0, (byte)0x83, (byte)0xee, (byte)0xc4, (byte)0x7f, (byte)0xec, (byte)0x62, (byte)0x45,
            (byte)0x92, (byte)0x18, (byte)0x97, (byte)0xdd, (byte)0x03, (byte)0x83, (byte)0xf7, (byte)0xdc,
            (byte)0xf7, (byte)0xa1, (byte)0xdb, (byte)0x9a, (byte)0x05, (byte)0x82, (byte)0x71, (byte)0x0e,
            (byte)0x03, (byte)0xdc, (byte)0x53, (byte)0xcb, (byte)0xad, (byte)0x35, (byte)0x76, (byte)0x70,
            (byte)0x3d, (byte)0x17, (byte)0xa2, (byte)0xe8, (byte)0x0d, (byte)0x21, (byte)0x50, (byte)0x44};
    */

    private final static byte[] cipher = {
            -113, -47, -15, 105, -18, 14, -118, 122, 103, 93, 120, 70, -36, -82, 109, 113, 36, -127,
            19, -35, -68, 21, -20, -69, 7, 94, -115, 58, -105, -10, -77, -62, 106, 86, -44, -24,
            -46, 112, 37, 3, -34, -51, -35, 90, -93, -59, 12, -35, 125, -33, -6, -109, -100, 25,
            127, 126, -81, -73, -50, -61, 84, 32, 127, -126, -81, -20, -116, -82, 38, 119, 27, 7,
            122, -2, -30, 58, 98, -17, 66, -103, 116, -83, -36, 106, 121, -23, -40, 125, -27, -37,
            -95, -59, -70, 61, 71, 43, -55, -22, -8, -72, 50, -19, -77, 37, 78, -37, 126, 119, 31,
            -37, 70, 41, 64, -97, -28, 68, -14, -41, -17, -94, 3, 2, 31, -85, -86, 84, -34, -58,
            115, -14, 87, 62, 52, 103, -28, -89, 3, 104, 19, 61, -7, -53, -15, 28, -108, -85, -106,
            3, -77, -11, 37, -65, -107, -61, 53, -3, -68, 105, -101, -118, -44, 69, -63, -81, -57,
            74, -86, 76, 27, -58, 91, 64, 60, -86, 3, 5, -108, -44, 77, -80, 50, 119, 109, 107, -43,
            -93, -87, -42, 32, 66, 27, -64, 38, -44, 50, -108, -21, -70, -102, -63, -120, 118, 7,
            89, -106, 66, -3, -10, 93, -9, 3, 13, 35, 37, -19, 116, 47, 29, 91, -30, 69, -49, 109,
            72, 6, 36, 58, -63, 107, 48, 70, 127, -127, 51, -110, 48, -73, -62, -118, 59, -27, 30,
            -109, -42, -109, -54, -22, 95, 123, -89, -62, -99, -62, 66, 60, 126, -52, -117, -98,
            -95, 2, -93, -93, -30, 85, -113, -77, -60, -83, -4, -50, 52, 113, 62, -104, -124, 56,
            89, -62, 108, 35, -10, 90, -42, -26, 114, 11, -49, -18, 56, -60, -87, -118, -106, -76,
            -103, -53, -7, -54, -70, -120, -92, -29, -17, -106, 80, -3, -18, -44, 115, -31, 57, -57,
            60, 94, -6, 18, -56, -27, -17};

    /*
    public byte[] encrypt(byte[] key, byte[] data) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            return cipher.doFinal(data);
        } catch (Exception ignored) {}
        return null;
    }
    */

    private byte[] decrypt(byte[] key, byte[] encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            return cipher.doFinal(encrypted);
        } catch (Exception ignored) {}

        return null;
    }


    byte[] checkKey(byte[] key) {
        if (nativeCheck(key)) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                if (java.util.Arrays.equals(digest.digest(key), correctHash)) {
                    return decrypt(key, cipher);
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    public native boolean nativeCheck(byte[] key);
}
