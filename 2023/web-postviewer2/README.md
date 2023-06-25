# Postviewer v2

* Writeup - [solve](./solve/solve.html)
* Solver - `(cd solution/ && python3 solve.py);` should print the flag after 7 seconds.

The challenge requires SSL certs on `*.postviewer2-web.2023.ctfcompetition.com` and `*.2023.ctfcompetition.com` and DNS entries pointing to the same pod for `*.postviewer2-web.2023.ctfcompetition.com` and `postviewer2-web.2023.ctfcompetition.com`

## Deployment notes

### PANIC - tl;dr chall down what do

Run `kubectl edit ingress postviewer2` and make sure `spec` contains:
```
 rules:
  - host: postviewer2-web.2023.ctfcompetition.com
  - host: '*.postviewer2-web.2023.ctfcompetition.com'
  tls:
  - secretName: tls-cert
  - secretName: postviewer-tls-cert
```
If there's only one `secretName` in tls, edit it to match.

### Details

Because of the two required certs, the setup here is quite hacky.

##### Obtaining the extra certificate

THIS NEEDS TO BE DONE ONLY ONCE (and was already done), until the cert expires
(90d).

`postviewer-certbot.yaml` contains a modified certbot deployment for requesting
this specific certificate. It will save it to Secret `postviewer-tls-cert` in
namespace `kctf-system`.  
kctf's secret sync doesn't know about this, so it has to be manually copied to
ns default, for example with:
```
kubectl -n kctf-system get secret postviewer-tls-cert -o yaml | sed -e 's/kctf-system/default/' | kubectl apply  -f -
```

#### Patching the ingress

Now we need to edit the Ingress object, so it also presents second certificate.
Note we need both - a cert for \*.example.com is not valid for example.com.

The Ingress is managed by kctf, but I couldn't find a way to have it remember the modification, so it needs to be applied manually after every `kctf chal start`.
To do this, `kubectl edit ingress postviewer2` and make sure `spec.rules.host`
contains both the wildcard and non-wildcard hosts, then ensure `spec.rules.tls`
contains two `secretName` entries, one for `tls-cert`, the other for
`postviewer-tls-cert`.

Pantheon currently complains that there's something wrong with the ingress
- "Missing one or more resources.". This doesn't seem to break the challenge
  though.
