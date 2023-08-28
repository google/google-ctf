# Unnecessary Binary Format

We needed to store arrays of various types of data and didn't like protobuf, json, or any other existing format.

So we wrote our own!

## Example Plaintext
```
bool [F, T, F, F, T, T]; int [100, 200, 300]; string ["AAAA", "Deadbeef", "$MOTD"];
```

## Example packed and b64 encoded
```
BgAAAGIGAAAAAAEAAAEBDAAAAGkDAAAAZAAAAMgAAAAsAQAAFwAAAHMDAAYABAAIAAUAQUFBQURlYWRiZWVmJE1PVEQ=
```

