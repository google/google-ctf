/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.ctf.shallweplayagame;

class N {
    // This is where the fun begins. While this is very tedious to do by hand, it would be "trivial"
    // to generate automatically. Don't do this to obfuscate your apps - it's slow, weak and brittle

    static final int _CIPHER = 0;
    static final int _SECRET_KEY_SPEC = 1;
    static final int _MESSAGE_DIGEST = 2;
    static final int _RANDOM = 3;

    static final int _AES_ECB_NOPADDING = 0;
    static final int _AES = 1;
    static final int _SHA256 = 2;

    /*
     * Format:
     *      (index, type_id, caller_id, argc)
     *
     * Type:
     *      0 - METHOD
     *      1 - STATIC_METHOD
     *
     * Caller:
     *      0 - Call[Static]ObjectMethod
     *      1 - Call[Static]VoidMethod
     *      2 - NewObject
     *      3 - CallIntMethod
     */
    static final int[] _GET_INSTANCE = new int[] {0, 1, 0};  // Cipher.getInstance
    static final int[] _CTOR_SECRETKEYSPEC = new int[] {1, 0, 2};  // SecretKeySpec.ctor
    static final int[] _INIT = new int[] {2, 0, 1};  // Cipher.init
    static final int[] _DO_FINAL = new int[] {3, 0, 0};  // Cipher.doFinal
    static final int[] _GET_INSTANCE2 = new int[] {4, 1, 0};  // MessageDigest.getInstance
    static final int[] _UPDATE = new int[] {5, 0, 1};  // MessageDigest.update
    static final int[] _DIGEST = new int[] {6, 0, 0};  // MessageDigest.digest
    static final int[] _CTOR_RANDOM = new int[] {7, 0, 2};   // Random.ctor
    static final int[] _NEXT_BYTES = new int[] {8, 0, 1};  // Random.nextBytes

    static { System.loadLibrary("rary"); }

    static native Object _(Object... args);
}
