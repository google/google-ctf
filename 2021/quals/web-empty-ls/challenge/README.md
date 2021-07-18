# License of this file

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

## Banned words

Banned words courtesy of http://www.bannedwordlist.com/ plus a few additions and
changes.

## Client CA

You can regen clientca.crt.pem and clientca.key.pem with `./gen_client_ca.sh`.
That will break any already-issued client certs and it will also require a
complete redeployment of empty-ls and empty-ls-admin to pickup the new clientca.
Before redeploying empty-ls-admin, rerun `make` in the
web-empty-ls-admin/challenge` directory to recopy the client.crt.pem . Note that
it doesn't neek clientca.key.pem .

```
chmod 644 clientca.*
```

## Server cert

```
mkdir /tmp/newcerts
cd /tmp/newcerts
wget \
    https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated
chmod +x dehydrated
wget https://raw.githubusercontent.com/gheja/dns-01-manual/master/hook.sh
chmod +x hook.sh
./dehydrated --register --accept-terms
./dehydrated \
    -c \
    --domain 'zone443.dev' \
    --domain '*.zone443.dev' \
    --challenge dns-01 \
    --hook ./hook.sh \
    --algo rsa
# It says to modify a TXT record. Do it. Then it says to add a 2nd one. Add a
# 2nd data item to that same existing record set.
# Then it says to delete them, so delete the entire record set.
cp \
    certs/zone443.dev/fullchain.pem \
    "${CHALLENGES_DIR}/web-empty-ls/challenge/zone443.dev.fullchain.crt.pem"
cp \
    certs/zone443.dev/privkey.pem \
    "${CHALLENGES_DIR}/web-empty-ls/challenge/zone443.dev.key.pem"
cd "${CHALLENGES_DIR}/web-empty-ls/challenge"
chmod 644 zone443.dev.*
rm -r /tmp/newcerts
```

These last 90 days, so that's good enough for the duration of the CTF. When they
expire, well, I guess we can ignore that because the CTF will be over.

These are also used in empty-ls-admin, they are copied from here to there with
the Makefile over there.
