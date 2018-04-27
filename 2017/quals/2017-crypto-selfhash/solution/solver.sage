def n2poly(x, n):
    r = x - x
    p = x ** 0
    while n > 0:
        if n & 1:
            r += p
        n = n >> 1
        p *= x
    return r
def poly2vec(poly):
    vec = map(GF(2), poly.lift().coefficients(sparse=False))
    return [GF(2)(0)] * (82 - len(vec)) + vec[::-1]

F.<x> = PolynomialRing(GF(2))
mod = n2poly(x, 0x142f0e1eba9ea3693)
mod = n2poly(x, 0x0308c0111011401440411) + x ** 82
G.<a> = PolynomialQuotientRing(F, mod)
p30 = n2poly(a, 0x0c)

base = vector(poly2vec(sum(p30 * a ** n for n in range(82, 82 + 82*8, 8))))
M = Matrix([poly2vec(a ** (82 + 7 + 8*n)) for n in reversed(range(82))]).transpose()
M2 = M + identity_matrix(GF(2), 82)[::-1]
V = M2.solve_right(base)

for b in [0] + M2.right_kernel().basis():
    Vfix = V + b
    assert M * Vfix + base == Vfix[::-1]
    print ''.join(map(str, Vfix))
