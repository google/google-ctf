#!/bin/bash

set -Eeuxo pipefail

mkdir /root/proc
mount -t proc none /root/proc

for res in cpu memory pids; do
  mkdir -p "/sys/fs/cgroup/${res}/NSJAIL"
  chmod 777 "/sys/fs/cgroup/${res}/NSJAIL"
done
