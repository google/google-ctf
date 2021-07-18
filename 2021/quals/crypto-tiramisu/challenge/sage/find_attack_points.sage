#!/usr/bin/env sage
import copy
import collections
import functools
import logging
import operator
import json
import sys

# A point on a curve similar to a target prime curve (same p, a, different b) with small
# prime order n.
AttackPoint = collections.namedtuple("AttackPoint", ["b", "gx", "gy", "n"])
AttackPoint.AsStrDict = lambda self: {"b": str(int(self.b)), "gx": str(int(self.gx)), "gy": str(int(self.gy)), "n": str(int(self.n))}

# Copied from http://www.secg.org/SEC2-Ver-1.0.pdf
P224Parameters = {
    "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
    "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
    "b": 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
    "Gx": 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
    "Gy": 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34,
    "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
}
P256Parameters = {
    "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    "Gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    "Gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
}

class SecureCurve(object):
    def __init__(self, params):
        self.FF = FiniteField(params["p"])
        self.a = self.FF(params["a"])
        self.b = self.FF(params["b"])
        Gx = self.FF(params["Gx"])
        Gy = self.FF(params["Gy"])
        assert (Gy**2 == Gx**3 + self.a * Gx + self.b)
        self.EC = EllipticCurve(self.FF, [self.a, self.b])
        self.G = self.EC.point([Gx, Gy])
        self.params = params
        # assert (params["n"] == self.G.order())
        # logging.debug("Curve parameters OK")

def IsNonRepeatingPrimeFactor(n, p):
    return ((n % p == 0) and (n % (p**2) != 0))

def RandomPointWithGivenOrder(EC, r):
    for try_ in range(1000):
        p = EC.random_point()
        h = p * (EC.order() // r)
        if not h.is_zero():
            assert (h * r).is_zero()
            return h
    raise Exception("Failed to point point with order %d" % (r))

# Search for an invalid curve point, which the additional constraint
# that is has to be on P256 curve.
#
# Formally, if P256 is defined with (a, b, p) and P224 is defined with (A, B, P).
# We need to find (x, y, B') such that:
#
# (x, y) is on P256:
#   (1)     y^2 == x^3 + a*x + b  (mod p)
#
# (x, y) is on a curve similar to P224: same (A, P), different B.
#   (2)     y^2 == x^3 + A*x + B' (mod P)
#
# On this curve, the point has small order.
#   (3)      0  == (x,y)*q for small q, where * operation is defined over (A, B', P)
#
# Method:
# Randomize B' until the curve size is divided by a small prime,
# get a random small order point on the new curve, get random point
# on P256, and find integer solutions (x, y) that solve both (1) and
# (2) using Chinese Remainder Theorem.
#
# Inspired by https://crypto.stackexchange.com/questions/63964/intersection-of-two-elliptic-curves
#
def FindAttackPoints():
    P224 = SecureCurve(P224Parameters)
    P256 = SecureCurve(P256Parameters)
    p = P256.params["p"]
    P = P224.params["p"]

    points = []
    # Minimize the number of points: search for slightly large primes.
    # smaller primes => less on-line work to solve ECDH over small order groups,
    # => more offline work to assemble the residues (2 ** #points).
    primes = set(prime_range(10000, 30000))
    # Product of all points' orders
    orders_prod = 1

    while orders_prod < P224.params["n"]:
        logging.debug("orders_prod = %d" % (orders_prod))

        onP256 = P256.EC.random_point()

        b = P224.FF.random_element()
        EC = EllipticCurve(P224.FF, [P224.a, b])

        # Don't change primes set during iteration.
        new_primes = copy.copy(primes)
        for q in primes:
            if IsNonRepeatingPrimeFactor(EC.order(), q):
                try:
                    onNew = RandomPointWithGivenOrder(EC, q)
                    logging.debug("Small order onNew: (0x%x, 0x%x)" % (onNew.xy()[0], onNew.xy()[1]))

                    x = crt(int(onP256.xy()[0]), int(onNew.xy()[0]), p, P)
                    y = crt(int(onP256.xy()[1]), int(onNew.xy()[1]), p, P)
                    assert(P256.EC.is_on_curve(x, y))
                    assert(EC.is_on_curve(x, y))
                    assert(not P224.EC.is_on_curve(x, y))
                    logging.debug("Lifted: (0x%x, 0x%x)" % (x, y))

                    points.append(AttackPoint(b, x, y, q))
                    orders_prod *= q
                    new_primes.remove(q)
                except Exception as e:
                    logging.warn(e)
                    pass

        primes = copy.copy(new_primes)
    return points

# Finds small order points on P224 similar curves.
def main(argv):
    logging.basicConfig(level=logging.DEBUG)
    set_random_seed(0x12345)
    points = FindAttackPoints()
    print(json.dumps([p.AsStrDict() for p in points]))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
