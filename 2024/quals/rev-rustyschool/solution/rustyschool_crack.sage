#!/usr/bin/env sage

# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ----------------------------------------------------------------------------------------
# Google CTF 2024: Rusty School Crack (RE)
# ----------------------------------------------------------------------------------------
import sys
import struct
import hashlib


def f(a, b):
  """Round funcion: F(a, b) = MD5(a || b)[:12]."""
  return list(hashlib.md5(bytes(a + b)).digest())[:12]


def g(a, b):
  """Round funcion: G(a, b) = SHA1(a || b)[:12]."""
  return list(hashlib.sha1(bytes(a + b)).digest())[:12]


def xor(a, b):
  """Element-by-element XOR of 2 lists."""
  return list(x ^^ y for x, y in zip(a, b))


def gfadd(a, b):
  """Adds 2 numbers in Galois Field."""
  return a ^^ b


def gfmul(a, b):
  """Multiplies 2 numbers in Galois Field by irreducible x^16 + x^5 + x^3 + x + 1."""
  p = 0
  while a != 0 and b != 0:
    if b & 1 !=0 :
      p ^^= a

    if a & 0x8000:
      a = (a << 1) ^^ 0x1002B
    else:
      a <<= 1 

    b >>= 1

  return p & 0xFFFF


def gfcrack(coeff, rkey_ty):
  """Solves a non-linear equation system in GF(2^16) to recover the round keys.

  Given a set of 6 `subkeys` from round `i`, rustyschool computes the round keys `KSi_A`
  and `KSi_B` as follows:

      let k_a: Vec<u16> = (0..6).map(|i|
          gfmul(subkeys[i], subkeys[(i + 1) % 6]) ^ subkeys[(i + 4) % 6]
      ).collect();
      let k_b: Vec<u16> = (0..6).map(|i|
          gfmul(subkeys[(i + 2) % 6], subkeys[(i + 3) % 6]) ^ subkeys[(i + 5) % 6]
      ).collect();
  
  Since all operations are in GF(2^16) by irreducible polynomial x^16 + x^5 + x^3 + x + 1,
  to recover the `subkeys` from the round keys, we have to solve a nonlinear equation
  system (we have a similar system for `KSi_B`):

      sk0 * sk1 + sk4 = KSi_A_0
      sk1 * sk2 + sk5 = KSi_A_1
      sk2 * sk3 + sk0 = KSi_A_2
      sk3 * sk4 + sk1 = KSi_A_3
      sk4 * sk5 + sk2 = KSi_A_4
      sk5 * sk0 + sk3 = KSi_A_5

  Please note that it may be possible to have >1 one solutions (or no solutions at all).

  Args:
    coeff: The list of equation coefficients (i.e., the round key).
    rkey_ty: The round key type ('A' or 'B').

  Yields:
    A list with the 6 round keys (if there is a solution).
  """
  K.<y> = GF(2)[]
  subkeys.<x> = GF(2^16, name='x', modulus=y^16 + y^5 + y^3 + y + 1)
  R.<sk0, sk1, sk2, sk3, sk4, sk5> = AffineSpace(6, subkeys)

  def gen_ideal(coeff):
    if rkey_ty == 'A':
      return ideal(
          sk0*sk1 + sk4 - coeff[0],
          sk1*sk2 + sk5 - coeff[1],
          sk2*sk3 + sk0 - coeff[2],
          sk3*sk4 + sk1 - coeff[3],
          sk4*sk5 + sk2 - coeff[4],
          sk5*sk0 + sk3 - coeff[5])
    elif rkey_ty == 'B':
      return ideal(
          sk2*sk3 + sk5 - coeff[0],
          sk3*sk4 + sk0 - coeff[1],
          sk4*sk5 + sk1 - coeff[2],
          sk5*sk0 + sk2 - coeff[3],
          sk0*sk1 + sk3 - coeff[4],
          sk1*sk2 + sk4 - coeff[5])
    else:
      raise Exception(f'Unknown rkey_ty: {rkey_ty}')
  
  # NOTE: `fetch_int` is deprecated. Use new `from_integer`.
  I = gen_ideal([subkeys.fetch_int(c) for c in coeff])
  S = R.subscheme(I)
  for P in S.rational_points():
    # # Substitute variables to ensure they're all zeros.
    # print(I.subs(sk0=P[0], sk1=P[1], sk2=P[2], sk3=P[3], sk4=P[4], sk5=P[5]))

    # NOTE: `integer_representation` is deprecated. Use new `to_integer`.
    yield [p.integer_representation() for p in P]


def crack_round_keys(final_rkey_b):
  """Given the final round key B, work backwards to recover all possible subkeys."""
  rkey_b = struct.unpack('<6H', final_rkey_b)  # Convert bytes to WORDs.
  
  print(f'[+] Cracking round keys for final key B:', ' '.join(f'{h:04X}' for h in rkey_b))

  # Starting from round 12, walk the Feistel Network backwards. At each step recover the 
  # subkeys from round keys, until you recover the original key from round 0.
  #
  # Since `gfcrack` can yield >1 solutions at a given round, we do not know which one is
  # correct, so we try them all. That is, we do an exhaustive search (BFS) to until we
  # reach round 0. Many of the keys are being discarded, as they produce 0 solutions on
  # the next step.
  queue = [(rkey_b, 12)]
  nkeys = 0
  while queue:
    round_key, feistel_round = queue.pop(0)

    if feistel_round == 0:
      # We successfully reached round #0. We have a solution.
      print(f'[+]     Subkey #{nkeys} FOUND:', ' '.join(f'{h:04X}' for h in round_key))
      nkeys += 1

      # Since we know the initial subkey, we can run the Fiestel Network forward to
      # find both `rkey_b` and `rkey_a`.
      keys_all = [round_key]
      for j in range(12):
        rkey_a = tuple(
            gfadd(
                gfmul(round_key[i], round_key[(i + 1) % 6]),
                round_key[(i + 4) % 6]
            ) for i in range(6)
        )

        rkey_b = tuple(
            gfadd(
                gfmul(round_key[(i + 2) % 6], round_key[(i + 3) % 6]),
                round_key[(i + 5) % 6]
            ) for i in range(6)
        )

        round_key = rkey_a
        keys_all.append((rkey_a, rkey_b))

      yield keys_all
      continue

    # We use round key A in every last except the last one (we use round key B).
    # Add all candidate subkeys to the queue.
    for subkey in gfcrack(round_key, rkey_ty='A' if feistel_round != 12 else 'B'):
      queue.append((subkey, feistel_round - 1))

  print(f'[+] Done. {nkeys} keys found.')


# ----------------------------------------------------------------------------------------
def crack_ciphertext(ciphertext, final_rkey_b):
  """Cracks a `ciphertext` using a final `key`."""
  assert len(ciphertext) == 48 and len(final_rkey_b) == 12
  
  round_keys = [k for k in crack_round_keys(final_rkey_b)]
  for n, rkeys in enumerate(round_keys):
    #if n != 5: continue
    print(f'[+] Trying key #{n}:', ' '.join(f'{h:02X}' for h in rkeys[0]))

    c0 = list(ciphertext[:12])
    c1 = list(ciphertext[12:24])
    c2 = list(ciphertext[24:36])
    c3 = list(ciphertext[36:])

    # Run Feistel Network backwards.
    for feistel_round in range(12):      
      print(f'[+]    Solving round #{feistel_round} ...')

      key_a, key_b = rkeys[12 - feistel_round]

      key_a_bytes = []
      for i in range(6):
        key_a_bytes.append((key_a[i] & 0xFF))
        key_a_bytes.append((key_a[i] >> 8))

      key_b_bytes = []
      for i in range(6):
        key_b_bytes.append((key_b[i] & 0xFF))
        key_b_bytes.append((key_b[i] >> 8))

      p0 = xor(f(key_a_bytes, c0), c1)
      p1 = xor(g(key_b_bytes, c0), c3)
      p2 = c0
      
      # Now solve the modular equation: A*(B + D) + C^D == c2 mod N.
      # We know A, B, C, c2 and we want to find D:
      #   A*(B + D) + C^B == c2                  mod N =>
      #   A*(B + D)       == c2 - C^B            mod N =>
      #   B + D           == (c2 - C^B)*A^-1     mod N =>
      #   D               == (c2 - C^B)*A^-1 - B mod N.
      N  = 79160129948973046149879599747
      A  = int.from_bytes(bytes(p0), byteorder='little')
      B  = int.from_bytes(bytes(p1), byteorder='little')
      C  = int.from_bytes(bytes(p2), byteorder='little')
      c2 = int.from_bytes(bytes(c2), byteorder='little')

      R = IntegerModRing(N, is_field=True)
      D = R(c2 - power_mod(C, B, N))*R(A)^-1 - R(B) % N
      
      print(f'[+]        A = {A}')
      print(f'[+]        B = {B}')
      print(f'[+]        C = {C}')
      print(f'[+]        D = {D}')
      print(f'[+]       c2 = {c2}')

      p3 = list(int(D).to_bytes(12, byteorder='little', signed=False))

      # Advance to the next round.
      c0, c1, c2, c3 = p0, p1, p2, p3
      plaintext = c0 + c1 + c2 + c3

      print('[+]        Decrypted:', ' '.join(f'{h:02X}' for h in plaintext))

  
    if verify_plaintext(plaintext):
      plaintext = ''.join(chr(p) for p in plaintext)

      if plaintext.endswith('\x01'):  # If there's padding, remove it.
        plaintext = plaintext[:plaintext.find('\x01')]

      print(f'[+] Plaintext FOUND: {plaintext!r}')
      return plaintext

  # If we reach this point, we have made a mistake :(
  raise Exception(f'Decryption of block #{n} failed :(')


def verify_plaintext(plaintext):
  """Checks whether a decrypted ciphertext is ASCII-printable."""
  return all((p >= 0x20 and p <= 0x7e) or p in [13, 10, 1] for p in plaintext)


def main() -> None:
  print('[+] Rusty School crack started.')

  if len(sys.argv) != 2:
    print(f'Usage: {sys.argv[0]} <ciphertext file to crack>')
    return

  total_plaintext = ''

  with open(sys.argv[1], 'rb') as fp:
    i = 0
    while buf := fp.read(60):
      cipher, key = buf[:48], buf[48:]

      print(f"[+] {'='*50} Cracking Block #{i} {'='*50}")
      print('[+] Cipher:', ' '.join(f'{c:02X}' for c in cipher))
      print('[+] Key   :', ' '.join(f'{k:02X}' for k in key))

      total_plaintext += crack_ciphertext(cipher, key)

      print('[+] Total plaintext so far:')
      print(total_plaintext)

      i += 1

  open(f'{sys.argv[1]}.decrypted', 'w').write(total_plaintext)
  print('[+] Program finished! Bye bye :)')


if __name__ == "__main__":
  main()
