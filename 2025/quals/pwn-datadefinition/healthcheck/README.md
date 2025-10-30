# Healthcheck

kCTF checks the health of challenges by accessing the healthcheck via
http://host:45281/healthz which needs to return either 200 ok or an error
depending on the status of the challenge.

The default healthcheck consists of:
* a loop that repeatedly calls a python script and writes the status to a file
* a webserver that checks the file and serves /healthz
* the actual healthcheck code using pwntools for convenience

The healthcheck code connects to the challenge and uses the same logic as in
`exploit.py` provided in this repo.
