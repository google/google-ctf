# v8box

TL;DR: V8 with the memory corruption API and V8 sandbox enabled and the JIT disabled. Players have to use the memory corruption API to get code execution.

## How to deploy on kCTF

```
kctf chal start
```

## How to rebuild the challenge

```
cd challenge
make
```

This might take some time because it needs to rebuild V8.

If you do this, you will also need to update the exploit because it will break.
Specifically, the offsets of the ROP gadgets and function pointer leak need to
be updated. The constants are all at the top of the exploit
(`healthcheck/pwn.js`).

## How to update V8

Change the version in v8_version, then follow the steps above to rebuild.
