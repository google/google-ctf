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



package ed25519final;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * The bug is in sign() function where hashedPrivateKey variable is reused.
 *
 * <p>Note that in Java, the declaration: "final byte[] x" means x is constant. However, as x is
 * just an reference to a "byte[]" array, x's content can be changed!
 *
 * <p>The consequence of this bug :
 *
 * <ul>
 *   <li>hashedPrivateKey value is changed.
 *   <li>The 1st 32 bytes of *modified* hashedPrivateKey is published in s. Note that the 1st 32
 *       bytes of original hashedPrivateKey is not leaked (it is our flag).
 * </ul>
 *
 * <pre>
 * Write down the set of equations (the notation is from https://ed25519.cr.yp.to/python/ed25519.py)
 *   s1 = (r1 + Hint(R, publicKey, message) * a1) mod l
 *   s2 = (r2 + Hint(R, publicKey, message) * a2) mod l
 * where a1, a2 corresponds to our hashedPrivateKey
 * We have:
 * <ul>
 *  <li> As we sign the same message: r1 = r2 = r.
 *  <li> Deal the leakage, we know that a2 = s1.
 * </ul>
 * Therefore:
 *  s1 = (r + Hint(R, publicKey, message) * a1) mod l (1)
 *  s2 = (r + Hint(R, publicKey, message) * s1) mod l (2)
 * From equation (2):
 *  r = (s2 - Hint(R, publicKey, message) * s1) mod l
 * Plug r into (1):
 *  a1 = ((s1 - r) * (Hint(R, publicKey, message)^(-1) mod l)) mod l
 *
 * a1 is the flag.
 * </pre>
 */
public class Ed25519FinalSolution {
  /** Decodes a hex string to a byte array. */
  static byte[] hexDecode(String hex) throws IllegalArgumentException {
    int size = hex.length() / 2;
    byte[] result = new byte[size];
    for (int i = 0; i < size; i++) {
      int hi = Character.digit(hex.charAt(2 * i), 16);
      int lo = Character.digit(hex.charAt(2 * i + 1), 16);
      result[i] = (byte) (16 * hi + lo);
    }
    return result;
  }

  public static void main(String[] args) throws Exception {
    byte[] message = hexDecode(args[0]);
    byte[] publicKey = hexDecode(args[1]);
    byte[] sig1 = hexDecode(args[2]);
    byte[] sig2 = hexDecode(args[3]);
    BigInteger s1 = Ed25519Final.decodeInt(Arrays.copyOfRange(sig1, 32, 64));
    BigInteger s2 = Ed25519Final.decodeInt(Arrays.copyOfRange(sig2, 32, 64));
    BigInteger h =
        Ed25519Final.Hint(Ed25519Final.concat(Arrays.copyOfRange(sig1, 0, 32), publicKey, message));
    BigInteger r = s2.subtract(h.multiply(s1)).add(Ed25519Final.l).mod(Ed25519Final.l);
    BigInteger a = s1.subtract(r).multiply(h.modInverse(Ed25519Final.l)).mod(Ed25519Final.l);
    System.out.println(Ed25519Final.hexEncode(Ed25519Final.encodeInt(a)));
  }
}
