# Solution

```text
   a * p ≈ b * q
-> a / b * p ≈ q
-> a / b * p * q ≈ q * q
-> a / b * N ≈ q^2
-> q^2 ≈ N / b * a
-> q ≈ sqrt(N / b * a)
```

If we know `a` and `b`, we know the estimate of `q`, then we can search around
`q` (i.e. the range `[est_q - delta, est_q + delta]`) and find one that divides `N`.

Since `a` and `b` are small, we could bruteforce all possible `(a, b)` pairs,
then search around the corresponding estimate of `q`.

Since `abs(a * p - b * q) < 10000`, we expect that the estimate of `q` won't be
too far away from the actual `q`. We could start searching from `est_q ± 10`,
then `est_q ± 100`, then `est_q ± 1000` and so on until we are able to find the
answer. In this challenge, `est_q ± 10` would be enough.

After we've found the `q` that divides `N`, we basically factorized `N`. We can
then obtain `p = N / q`, `phi = (p - 1) * (q - 1)`, and the decryption key
`d = invert(e, phi)`. Obtain the plaintext by `pow(c, d, n)`.

Note that native python doesn't handle `sqrt` of huge numbers properly. So one
should use libraries like `gmpy2` or `sagemath` to compute the square root. I
guess python try to convert your integer to float before performaing square
root, and the precision of the float is not enough for such huge numbers.

See `solution.py` for a sample solution script.


# License

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
