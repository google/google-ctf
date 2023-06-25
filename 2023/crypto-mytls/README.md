# crypto-mytls

This challenge implements a TLS-like protocol that is vulnerable to KCI.

The challenge is in 2 stages:

1) Leak the server key using a file truncation oracle

```
$ python3 client.py ./challenge/guest-ecdhcert.pem ./challenge/guest-ecdhkey.pem mytls.2023.ctfcompetition.com 1337
```

2) Use the KCI attack to authenticate as admin and get the flag

```
$ python3 client.py ./challenge/admin-ecdhcert.pem ./challenge/server-ecdhkey.pem mytls.2023.ctfcompetition.com 1337 --kci
```
