"""
Before running this, copy attachments/tanh_crypto.py to this directory.

When coding this addition law, I wrote a version using projective coordinates
The break becomes obvious when you do this.  Let a, b, and s, be rational
numbers, with numerators an, bn, and sn, and denominators ad, bd, sd.  Then we
can write our addition law as:

    sn/sd = (an/ad + bn/bd)/((an bn)/(ad bd) + 1) = (an bd + ad bn)/(an bn + ad bd)

To avoid modular inverses on every addition step, compute numerators and
denominators separately and do just one modular inverse at the end:

    sn = an bd + ad bn
    sd = an bn + ad bd

This looks a lot like complex multiplication, which is roughly equivalent to
polynomial rings mod x^2 + 1.  This is actually similar to polynomial rings mod
x^2 - 1.:

    (ax + b)(cx + d) = acx^2 + (ad + bc)x + bd mod x^2 - 1
      = (ad + bc)x + (ac + bd)

Unfortunately, x^2 - 1 is reducible:

    x^2 - 1 = (x + 1)(x - 1)

With a bit of algebra, we can solve DLP over this addtion rule easily.  The
remainder mod x^2 - 1 can be written as:

    n*(x + 1) + m*(x - 1) = ax + b mod x^2 - 1    (Equation 1)

where ax + b is the remainder of a polynomial mod x^2 - 1, and where n and m
are integers from 0 .. p-1, where we do arithmetic mod p.  We can find n and m,
where all these equations are mod p:

    n + m = a
    n - m = b
    2m = a - b
    m = (a - b)/2
    n = m + b = (a + b)/2

Substituting back into equation 1:

    (x + 1)(a + b)/2 + (x - 1)(a - b)/2 = ax + b

We want to find Alice's secret exponent e, where Alice's public key is:

    pubkey = c/d mod p, where
    cx + d = (gx + 1)^e mod x^2 - 1

Where g is the generator, which is 2 in our case.  Applying equation 1, we get:

    cx + d = ((x + 1)(g + 1)/2 + (x - 1)(g - 1)/2)^e mod x^2 - 1

Taking this mod x - 1:

    c + d = (1 + g)^e mod x - 1

and mod x + 1:

    d - c = (1 - g)^e mod x + 1

Since we have constant polynomials, we can drop the mod x + 1 and mod x - 1:

    c + d = (1 + g)^e mod p
    d - c = (1 - g)^e mod p

Dividing the equations:

    (c + d)/(d - c) = ((1 + g)/(1 - g))^e mod p
    (c/d + 1)/(1 - c/d) = ((1 + g)/(1 - g))^e mod p

    (pubkey + 1)/(1 - pubkey) = ((1 + g)/(1 - g))^e mod p

This last equation has only e as an unknown, and can be solved with a regular DLP solver.
"""

from tanh_crypto import *

x = polygen(GF(p))
left = ((pubkey + 1)*inverse_mod(1 - pubkey, p)) % p
right = ((1 + g)*inverse_mod(1 - g, p)) % p
recoveredSecret = log(Mod(left, p), Mod(right, p))
print "Recovered secret =", recoveredSecret
print decrypt(recoveredSecret, encMessage, g, p)
