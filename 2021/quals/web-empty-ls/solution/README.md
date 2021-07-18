# License for this file

Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: Kegan Thorrez

# Solution

On an attacker site in the subdomain, serve a page with js that requests itself.
Have the server only serve that page on the first request, and for subsequent
requests TCP proxy to admin.zone443.dev:443 . Note that this assumes the first
request and the 2nd request don't go over the same TCP connection, in my testing
they don't go over the same TCP connection, so it works.

I run this on a GCP VM that has an open firewall on port 443 and 8443. 8443 is
where to receive the flag after it has been stolen.

Make sure you open the GCP firewalls to those 2 ports.

You need to use the central site to create a site and point it to the external
IP of your GCP VM.

Then run `go build solve.go` and `sudo ./solve`.

Then contact the admin and say `https://${SUBDOMAIN}.zone443.dev` where you need
to replace `${SUBDOMAIN}` with the subdomain you registered earlier.

## Opsec

To avoid other players seeing my exploit and using it, I only serve the attack
js and only do TCP proxying when the srcip is one that has identified itself
either now or earlier as the admin.

## https cert

You need a valid https cert for the attacker subdomain. Here's a way to do it:


```
mkdir -p newcert/static/.well-known/acme-challenge
cd newcert/static
sudo python -m SimpleHTTPServer 80
```

Another terminal:
```
SUBDOMAIN=yoursubdomain # edit this line
cd newcert
wget \
    https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated
chmod +x dehydrated
echo 'WELLKNOWN=static/.well-known/acme-challenge/' >> config
#echo 'CA="buypass"' >> config
#echo 'CONTACT_EMAIL="you@example.com"' >> config # needed if using buypass
./dehydrated --register --accept-terms
./dehydrated \
    -c \
    --domain "${SUBDOMAIN}.zone443.dev" \
    --challenge http-01 \
    --algo rsa
cp certs/${SUBDOMAIN}.zone443.dev/fullchain.pem ../server.fullchain.crt.pem
cp certs/${SUBDOMAIN}.zone443.dev/privkey.pem ../server.key.pem
```

## Testing difficulties

TCP proxying to admin.zone443.dev:443 is dificult during a testing phase where
there is a strong firewall. So instead of TCP proxying there, I TCP proxy to
localhost:4242 and have an SSH reverse tunnel from there to my desktop which
does have access to admin.zone443.dev:443.

To set up the reverse tunnel, I run this on my workstation:

```
gcloud compute ssh ctf --project=your-other-project \
    --ssh-flag="-R 4242:admin.zone443.dev:443"
```

`ctf` is my VM's name and `your-other-project` is a project that can connect to
the public internet.

Then the `sudo ./solve` needs to be changed to
`sudo ./solve --admin_addr=localhost:4242`.
