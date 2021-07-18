# Invalid curve point variant crypto challenge

## Overview

Server encrypts the flag using a key derived from its private ECDH key.
Server sends the encrypted flag to the client, they exchange ECDH keys,
and establish a secure channel. The server implements a simple echo service.

The client decrypts the flag when it successfully recovers the server's private ECDH key.

## The vulnerability

Server verifies client's key represents a valid point on the curve, however,
there's a subtle bug in this check - the server verifies the point is on the **client
supplied** curve, then performs the secret multiplication on the server's hardcoded curve -
which could be **different** from the client's curve.

This opens the door to a classic "invalid curve point" attack, with an additional constraint:
the invalid, low order point, needs to be a valid point on the client's curve.

Finding a point on the curves intersection is possible by **lifting** its coordinates to the p1\*p2
integer ring using the Chinese Remainder Theorem, see [this](https://crypto.stackexchange.com/questions/63964/intersection-of-two-elliptic-curves) for additional information.

The challenge name, "Tiramisu", means "lift me up", a small hint to the solution.

`challenge/sage/find_attack_points.sage` finds the lifted attack points (`healthcheck/attack_points.json`). This is a one-time, offline step.

`healthcheck/healthcheck.py` implements the full attack: an online step which collects the modular residues,
followed by an offline step which reassembles private key candidates, and searches for the correct solution.
Intermediate values are cached in order to speed up computation.

## How to rebuild the server

```
$ make -C challenge
```

## How to re-flag

Update `challenge/flag`, change `flagFixedIV` in `challenge/server/server.go`, and restart the challenge using `kctf chal start`.

## How to run the challenge unit tests

```
$ cd challenge
$ go test -v ./server
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

## How to update the server's private key

Run `challenge/cmd/generate_ecdh_key.go`:

```
$ cd challenge
$ go run cmd/generate_ecdh_key -key server_ecdh_private.textproto
```

Next, run the full attack: clear `CACHED_RESIDUES` and `CACHED_OFFLINE_START_ROUND` in `healthcheck/healthcheck.py`, run the script locally (see "how to debug healthcheck.py" above) - this could take up to an hour,
and update the variables above. Finally, restart both containers.
