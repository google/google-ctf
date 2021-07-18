# ECDSA with related keys crypto challenge

The server (challenge directory) presents two messages `(m0, m1)` and a public ECDSA key.
It signs `m0` using the **related private key** `a*sk`, where the scalar `a` is given by the client.
The server returns the flag when the client presents a forged signature `(r, s)` for `m1`, which verifies under the original public key.

An attack for this scheme is described in ["On the Security of the Schnorr Signature Scheme and DSA against Related-Key Attacks"](https://eprint.iacr.org/2015/1135) by Hiraku Morita and Jacob C.N. Schuldt and Takahiro Matsuda and Goichiro Hanaoka and Tetsu Iwata.

The attack is implemented in `challenge/challenger/challenger_test.go` and in `healthcheck/healthcheck.py`.

## How to rebuild the server

```
$ make -C challenge
```

## How to re-flag

Update `challenge/flag` and restart the challenge using `kctf chal start`.

## How to run the challenge unit tests

```
$ cd challenge
$ go test -v ./challenger
```

## How to debug healthcheck.py

Disable the `healthcheck` in `challenge.yaml`, and re-deploy the server:

```
$ kctf chal start
```

Start port-forwarding to the challenge container:

```
$ kctf chal debug port-forward
[*] starting port-forward, ctrl+c to exit
Forwarding from 127.0.0.1:XXXXXX -> 1337

```

Run `healthcheck.py` and connect to the forwarded port:

```
$ cd healthcheck
$ python3 healthcheck.py --port XXXXXX
```
