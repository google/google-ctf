# v8box

## How to run

```sh
./d8 pwn.js
```

There is also a Dockerfile that reproduces the remote environment:

```sh
docker build -t v8box .
docker run -p 1337:1337 v8box
nc localhost 1337
```

## How to build V8

You can use the provided Makefile and build.dockerfile to build V8 in Docker.
