# EBPF

The challenge is a minimal Linux system based on the kernel version 5.12.2. A vulnerability was introduced into the eBPF verifier and the players are expected to elevate privileges to root and read the otherwise protected `/flag`.

## Build and Deploy

```
cd pwn-ebpf
make -C challenge && kctf chal start
```

## Healthcheck

Note, that healthcheck has the Makefile as it needs to compile the exploit first.

```
make -C healthcheck
```
