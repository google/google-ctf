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



/**
 * Print a Flag.
 * @author Daniel Bleichenbacher
 */
package blt;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;

public class Flag {

  // Generate a random integer in the range 1 .. q-1.
  private static BigInteger generateSecret(BigInteger q) {
    // Get the number of bits of q.
    int qBits = q.bitCount();
    SecureRandom rand = new SecureRandom();
    while (true) {
      BigInteger x = new BigInteger(qBits, rand);
      if (x.compareTo(BigInteger.ZERO) == 1 && x.compareTo(q) == -1) {
        return x;
      }
    }
  }

  private static BigInteger hashMessage(byte[] message) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);
    return new BigInteger(1, digest);
  }

  private static BigInteger[] sign(
      byte[] message,
      BigInteger p,
      BigInteger q,
      BigInteger g,
      BigInteger x) throws Exception {
    while (true) {
      BigInteger h = hashMessage(message);
      BigInteger k = generateSecret(q);
      BigInteger r = g.modPow(k, p).mod(q);
      BigInteger s = k.modInverse(q).multiply(h.add(x.multiply(r))).mod(q);
      if (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) continue;
      return new BigInteger[]{r,s};
    }
  }

 /**
  * This code generates a flag.
  */
  public static void main(String[] args) throws Exception {
    // p is a 2048 bit prime number.
    BigInteger p = new BigInteger(args[0]);
    // q is a 256-bit prime number that divides p-1.
    BigInteger q = new BigInteger(args[1]);
    // g is a generator of order q. (I.e. 1 = g**q mod p)
    BigInteger g = new BigInteger("2").modPow(p.divide(q), p);
    // generate the private key
    BigInteger x = generateSecret(q);
    BigInteger y = g.modPow(x, p);
    System.out.println("Y:" + y.toString());
    System.out.println("P:" + p.toString());
    System.out.println("Q:" + q.toString());
    byte[] message = ("CTF{" + x.toString() + "}").getBytes();
    System.err.println("Flag: " + new String(message));
    System.out.println("H:" + hashMessage(message).toString());
    BigInteger[] sig = sign(message, p, q, g, x);
    System.out.println("R:" + sig[0].toString());
    System.out.println("S:" + sig[1].toString());
  }
}
