# Google CTF 2023 - crypto: Primes writeup

We are given an encoding of a string containing the flag, and a scrambled version of the string where the flag has been replaced by random characters.

Here, to encode a bitstring $b \in \{0,1\}^n$ of length $n$, we calculate
$$x = \prod_{i = 0}^n p_i^{b_i} \mod q$$
where $p_i$ is the $i$-th prime, and $q$ is a fixed prime modulus.

Given the scrambled bitstring, we can compute its encoding $y$ in the same manner, and compute an error product
$$e = xy^{-1} \mod q = \prod_{i = 0}^n p_i^{e_i} \mod q$$
for errors $e_i \in \{-1,0,1\}$. Write this product in the form $e = nd^{-1} \mod q$, i.e.
$$ed = n + sq$$
with $n$ and $d$ such that they factor as positive powers of the $p_i$, for some unknown $s \in \mathbb{Z}$.

Manipulating above equation, we find
$$\left|\frac{e}{q} - \frac{s}{d}\right| = \frac{n}{qd}.$$
Assuming $nd < q/2$, we have that $s/d$ is a continued fraction convergent of $e/q$. This holds since then $\left|\frac{e}{q} - \frac{s}{d}\right| < \frac{1}{2d^2}$ in which case Diophantine approximation (https://en.wikipedia.org/wiki/Diophantine_approximation) tells us that $s/d$ is a best approximation for $e/q$.

In the challenge the bound on $q$ was chosen such that $nd < q/2$ for the scrambled string. Hence, the strategy is as follows: Compute the continued fraction convergents $s_j/d_j$ of $e/q$, try to factor $d_j$ and $d_je \mod q$ into the $p_i$, and use a good factorisation to fix the errors in the scrambled bitstring to recover the flag.
