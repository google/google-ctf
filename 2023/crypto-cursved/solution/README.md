# Google CTF 2023 - crypto: Cursved writeup

Checking the code, we see that it implements a Schnorr signature scheme. The underlying group is formed by the points on a Pell conic. In our case it is the Pell conic $C$ given by the equation

$$C: x^2 - dy^2 = 1$$

with $d = 3$ over the finite field $k = \mathbb{F}_p$ of characteristic $p =$ 0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B3.

By brushing up on Pell conics over finite fields (see https://arxiv.org/abs/2203.05290 for example), we remember that the points can form two different types of groups, depending on whether $d$ is a square or a non-square in $k$, respectively.

In our case, we can quicky check that $d$ is a quadratic residue modulo $p$, and so it turns out that $C(k) \cong k^*$ via the isomorphism

$$C(k) \to k^* \\ (x,y) \mapsto x + sy$$

where we fix a square root $s$ of $d$ in $k$. Hence, instead of solving a generically hard DLP over the Pell conic group law, we can solve it over $k^*$ instead.

The strategy is now as follows: Compute the images of the generator point $G$ and public key point $P$ in $k^*$ via above morphism, and use CADO-NFS (https://cado-nfs.gitlabpages.inria.fr/) to solve the discrete logarithm there. This directly recovers the private key and allows us to sign the server's challenge to receive the flag.
