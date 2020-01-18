#!/bin/bash

set -Eeuxo pipefail

for res in cpu memory pids; do
  mkdir "/sys/fs/cgroup/${res}/NSJAIL"
  chmod 777 "/sys/fs/cgroup/${res}/NSJAIL"
done
