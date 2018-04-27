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



/** @author quannguyen@google.com (Quan Nguyen) */
package ed25519final;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Print the flag.
 *
 * <p>Implements Ed25519 (https://ed25519.cr.yp.to/). The implementation is based on
 * https://ed25519.cr.yp.to/python/ed25519.py
 */
public class Ed25519Final {
  static final Integer b = 256;
  static final BigInteger q = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
  // https://tools.ietf.org/html/rfc7748#section-4.1
  static final BigInteger l =
      BigInteger.valueOf(2).pow(252).add(new BigInteger("14def9dea2f79cd65812631a5cf5d3ed", 16));

  static final BigInteger d = BigInteger.valueOf(-121665).multiply(inv(BigInteger.valueOf(121666)));
  static final BigInteger I =
      BigInteger.valueOf(2).modPow(q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), q);

  static BigInteger By = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5)));
  static BigInteger Bx = xrecover(By);
  static BigInteger[] B = new BigInteger[] {Bx, By};

  /** @return SHA-512(m) */
  static byte[] H(final byte[] m) throws GeneralSecurityException {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    digest.update(m);
    return digest.digest();
  }

  /* @return x^(-1) mod q */
  static BigInteger inv(final BigInteger x) {
    return x.modPow(q.subtract(BigInteger.valueOf(2)), q);
  }

  /* @return x given y */
  static BigInteger xrecover(final BigInteger y) {
    // xx = (y*y - 1) * inv(d*y*y + 1)
    BigInteger xx =
        y.multiply(y)
            .subtract(BigInteger.ONE)
            .multiply(inv(d.multiply(y).multiply(y).add(BigInteger.ONE)));
    BigInteger x = xx.modPow(q.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), q);
    if (!x.multiply(x).subtract(xx).mod(q).equals(BigInteger.ZERO)) {
      x = x.multiply(I).mod(q);
    }
    if (!x.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
      x = q.subtract(x);
    }
    return x;
  }

  /** @return P + Q */
  static BigInteger[] edwards(final BigInteger[] P, final BigInteger Q[]) {
    BigInteger x1 = P[0];
    BigInteger y1 = P[1];
    BigInteger x2 = Q[0];
    BigInteger y2 = Q[1];
    // t = d * x1 * x2 * y1 * y2
    BigInteger t = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
    // x3 = (x1 * y2 + x2 * y1) / (1 + t)
    BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1)).multiply(inv(BigInteger.ONE.add(t)));
    // y3 = (y1 * y2 + x1 * x2) / (1 - t)
    BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2)).multiply(inv(BigInteger.ONE.subtract(t)));
    return new BigInteger[] {x3.mod(q), y3.mod(q)};
  }

  /** @return e*P */
  static BigInteger[] scalarMult(final BigInteger[] P, final BigInteger e) {
    if (e.equals(BigInteger.ZERO)) return new BigInteger[] {BigInteger.ZERO, BigInteger.ONE};
    BigInteger[] Q = scalarMult(P, e.divide(BigInteger.valueOf(2)));
    Q = edwards(Q, Q);
    if (e.mod(BigInteger.valueOf(2)).equals(BigInteger.ONE)) {
      Q = edwards(Q, P);
    }
    return Q;
  }

  static BigInteger[] scalarMult(final BigInteger[] P, final byte[] e) {
    return scalarMult(P, decodeInt(e));
  }

  static BigInteger Hint(final byte[] m) throws GeneralSecurityException {
    byte[] h = H(m);
    BigInteger res = BigInteger.ZERO;
    for (int i = 0; i < 2 * b; i++)
      res = res.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h, i))));
    return res;
  }

  static int bit(byte[] h, int i) {
    return (h[i / 8] >> (i % 8)) & 1;
  }

  // Java BigInteger uses big-endian encoding while Ed25519 uses small-endian encoding, so we must
  // use the following helper methods.
  static int bit(BigInteger y, int i) {
    return y.testBit(i) ? 1 : 0;
  }

  static byte[] bitsToBytes(final int[] bits) {
    byte[] res = new byte[bits.length / 8];
    for (int i = 0; i < res.length; i++) {
      for (int j = 0; j < 8; j++) {
        res[i] |= bits[i * 8 + j] << j;
      }
    }
    return res;
  }

  static byte[] encodeInt(BigInteger y) {
    int[] bits = new int[b];
    for (int i = 0; i < b; i++) bits[i] = bit(y, i);
    byte[] res = new byte[b / 8];
    for (int i = 0; i < b / 8; i++) {
      for (int j = 0; j < 8; j++) {
        res[i] |= bits[i * 8 + j] << j;
      }
    }
    return res;
  }

  static byte[] encodePoint(BigInteger[] P) {
    BigInteger x = P[0];
    BigInteger y = P[1];
    int[] bits = new int[b];
    for (int i = 0; i < b - 1; i++) bits[i] = bit(y, i);
    return bitsToBytes(bits);
  }

  /** @return the concatenation of the input arrays. */
  public static byte[] concat(final byte[]... chunks) {
    int length = 0;
    for (byte[] chunk : chunks) {
      length += chunk.length;
    }
    byte[] res = new byte[length];
    int pos = 0;
    for (byte[] chunk : chunks) {
      System.arraycopy(chunk, 0, res, pos, chunk.length);
      pos += chunk.length;
    }
    return res;
  }

  /** @return SHA-512(Key) and clear corresponding bits */
  static byte[] getHashPrivate(final byte[] Key) throws GeneralSecurityException {
    byte[] h = H(Key);
    // Clear the corresponding bits
    h[0] = (byte) (h[0] & 248);
    h[31] = (byte) (h[31] & 127);
    h[31] = (byte) (h[31] | 64);
    return h;
  }

  static byte[] publicFromHashedPrivate(final byte[] hashedPrivateKey) {
    BigInteger[] A = scalarMult(B, Arrays.copyOfRange(hashedPrivateKey, 0, b / 8));
    return encodePoint(A);
  }

  /** Encodes a byte array to hex. */
  static String hexEncode(final byte[] bytes) {
    String chars = "0123456789abcdef";
    StringBuilder result = new StringBuilder(2 * bytes.length);
    for (byte b : bytes) {
      // convert to unsigned
      int val = b & 0xff;
      result.append(chars.charAt(val / 16));
      result.append(chars.charAt(val % 16));
    }
    return result.toString();
  }

  static BigInteger decodeInt(final byte[] s) {
    BigInteger res = BigInteger.ZERO;
    for (int i = 0; i < s.length * 8; i++)
      res = res.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(s, i))));
    return res;
  }

  static void computeR(final byte[] R, BigInteger r) {
    BigInteger[] pointR = scalarMult(B, r);
    System.arraycopy(encodePoint(pointR), 0, R, 0, R.length);
  }

  static void computeS(final byte[] s, BigInteger h, BigInteger r, final byte[] hashedPrivateKey) {
    byte[] t =
        encodeInt(
            r.add(h.multiply(decodeInt(Arrays.copyOfRange(hashedPrivateKey, 0, b / 8)))).mod(l));
    System.arraycopy(t, 0, s, 0, t.length);
  }

  /**
   * @return the Ed25519 signature for the {@code message} based on the {@code hashedPrivateKey}.
   */
  static byte[] sign(final byte[] message, final byte[] publicKey, final byte[] hashedPrivateKey)
      throws GeneralSecurityException {
    BigInteger r = Hint(concat(Arrays.copyOfRange(hashedPrivateKey, b / 8, b / 4), message));
    byte[] R = new byte[b / 8];
    computeR(R, r);
    BigInteger h = Hint(concat(R, publicKey, message));
    computeS(hashedPrivateKey, h, r, hashedPrivateKey);
    return concat(R, Arrays.copyOfRange(hashedPrivateKey, 0, b / 8));
  }

  public static void main(String[] args) throws Exception {
    SecureRandom rand = new SecureRandom();
    byte[] Key = new byte[b / 8];
    rand.nextBytes(Key);
    byte[] hashedPrivateKey = getHashPrivate(Key);
    byte[] publicKey = publicFromHashedPrivate(hashedPrivateKey);
    byte[] message = new String("Ed25519final").getBytes();
    System.err.println(
        "CTF{"
            + hexEncode(encodeInt(decodeInt(Arrays.copyOfRange(hashedPrivateKey, 0, 32)).mod(l)))
            + "}");
    System.out.println("publicKey: " + hexEncode(publicKey));
    System.out.println("Message:" + hexEncode(message));
    int N = 16;
    for (int i = 0; i < N; i++) {
      System.out.println("Signature: " + hexEncode(sign(message, publicKey, hashedPrivateKey)));
    }
  }
}
