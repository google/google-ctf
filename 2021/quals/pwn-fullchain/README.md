# Fullchain

TL;DR: players provide a HTML page, we open it in Chromium in a VM. Players have to
chain 3 bugs to become root in the VM.

Chromium is built from commit 1be58e78c7ec6603d416aed4dfae757334cd4e1e

## How to deploy on kCTF

```sh
kctf chal start
```

## How to rebuild the challenge

**!!! This does not rebuild Chromium, see below for that !!!**

```sh
cd challenge
make
```

We don't store the VM image and built Chromium in Git because they are too big. If
you rebuild the challenge you will also need to recreate the attachment archive.
`challenge/make_attachment.py` creates the zip file with all the attachments.
You will still need to upload it to GCS and update `Dockerfile` and `metadata.yaml` with the new URLs.

If you rebuild/change the kernel or the kernel module you might need to update the kernel exploit
in healthcheck (`healthcheck/kernel_exploit.c`) (see instructions near the top of the file).
To rebuild the kernel exploit use

```sh
cd healthcheck
make
```

## How to rebuild Chromium

Good luck! /s

**Warning**: this takes a while (about 1h if you have to check out the source the source on my corp workstation) even with Goma.

**Warning**: Updating the exploit might also take a while, assuming that it doesn't break entirely.

`challenge/update_chromium.sh` is adapted from sroettger@'s [script](https://team.git.corp.google.com/ctfcompetition/2020-challenges-quals/+/refs/heads/master/sandbox-teleport/update_chrome.sh)
from last year's edition. It checks out the source code at the specified version and builds it.
You need to [install `depot_tools`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/linux/build_instructions.md#install)
and [set up Goma](https://www.chromium.org/developers/gn-build-configuration) before running that script.

Goma only works on Corp workstations. If you want to build Chromium on another machine you can do that by disabling Goma
in the build configuration but it will take even longer (hours even on a beefy machine).

You will almost certainly need to update the Chromium exploit in healthcheck (`healthcheck/kernel_exploit.html`) if you rebuild Chromium.
There are instructions on how to do that near the top of the exploit.

If you get errors about importing python module `google.protobuf`, it's because you've installed some other package that uses the Google
namespace (I think some of the gcp sdk does this) and made `google.protobuf` inaccessible (see [here](https://github.com/protocolbuffers/protobuf/issues/1296)).
The solution for me was to uninstall all google-related packages from pip.
