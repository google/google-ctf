#!/bin/bash

set -Eeuxo pipefail

# create a tmpfs to support a read-only root fs
mount -t tmpfs none /root
mkdir /root/proc
mount -t proc none /root/proc

for res in cpu memory pids; do
  mkdir -p "/sys/fs/cgroup/${res}/NSJAIL"
  chmod 777 "/sys/fs/cgroup/${res}/NSJAIL"
done
