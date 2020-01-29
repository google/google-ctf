#!/bin/bash

set -Eeuxo pipefail

# create a tmpfs to support a read-only root fs
mount -t tmpfs none /root
mkdir /root/proc
mount -t proc none /root/proc
