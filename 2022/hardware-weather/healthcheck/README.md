# Healthcheck

This healthcheck is a full exploit - just run `healthcehck.py IP PORT`. It will
not show the flag by default - for that you need to uncomment the `print(flag)`
somewhere in the code.

# Old Healthcheck Message

kCTF checks the health of challenges by accessing the healthcheck via
http://host:45281/healthz which needs to return either 200 ok or an error
depending on the status of the challenge.

The default healthcheck consists of:
* a loop that repeatedly calls a python script and writes the status to a file
* a webserver that checks the file and serves /healthz
* the actual healthcheck code using pwntools for convenience

To modify it, you will likely only have to change the script in healthcheck.py.
You can test if the challenge replies as expected or better add a full example
solution that will try to get the flag from the challenge.
