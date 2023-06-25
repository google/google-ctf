# myTLS - Google CTF 2023 Writeup

## Background

The challenge implements a custom protocol for communicating between a client
and a server. It's similar to TLS 1.2 with the protocol
`TLS_ECDH_RSA_WITH_AES_256_CBC_SHA` and provides mutual authentication as well
as confidentiality, integrity and forward secrecy.

## Key Compromise Impersonation (KCI)

As presented in the paper at
https://www.usenix.org/system/files/conference/woot15/woot15-paper-hlauschek.pdf,
an issue with this protocol is that an attacker can impersonate either the
client or the server if they have the private key of the other peer and the
public key of they user they want to impersonate.

This is because the protocol uses static Diffie Hellman keys, therefore an
attacker can compute the same shared secret as the other peer, if they have
their private key. This is not possible with ephemeral Diffie Hellman key
exchanges.

## The attack

The protocol is as follows as follows:

```
CLIENT                          SERVER
                   <----- server certificate
client certificate ----->

client random      ----->
                   <----- server random

ephemeral client   ----->
public key
                   <----- ephemeral server
                          public key


<client secret computation>     <server secret computation>

HMAC('client myTLS
     successful!') ----->
                   <----- HMAC('server myTLS
                          successful!')

        <data is exchanged using AES with the shared secret as key>
```

The shared secret is by the server is computed with:

```
HKDF(client_eph_pub**server_eph_priv||client_pub**server_priv||
     client_random||server_random)
```

and by the client with:

```
HKDF(server_eph_pub**client_eph_priv||server_pub**client_priv||
     client_random||server_random)
```

(Note: HKDF is a key derivation function, the `**` is the exponentiation
operation needed for Diffie Hellman, see server.py for details).


One might notice that a client that has the server keypair and the public key
of the peer they intend to impersonate can compute the same shared secret of
the server, therefore authenticating successfully and impersonating the peer.

This allows an attacker to use the admin public key to authenticate and get the
flag if the attacker has the server private key.

### Leaking the server private key

After a successful authentication the server allows to store files on its
filesystem, providing the hash of the previous content of the file.
There is a path traversal bug that allows to write to arbitrary files.
Additionally, there is a missing file truncation issue that allows to partially
overwrite files. This allows to leak the server private key byte by byte.

An attacker can use `../../app/server-ecdhkey.pem` as storage slot and write a
known payload that is 240 bytes long on the server private key file. At the
next iteration of a similar write the server output the sha256 hash of the
known plaintext and the last byte of the private key. The `guest-ecdhkey.pem`
file is 241 bytes long so it's reasonable to assume that the server key has the
same length, otherwise some small bruteforce can determine the file length.

Repeating this procedure allows to leak the entire key.

The private key can be used to mount a KCI attack and authenticate as admin to
get the flag.
