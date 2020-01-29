# Local Testing Walkthrough

The purpose of this walkthrough is to teach you how to use the kCTF infrastructure.

Following this walkthrough requires a local linux machine capable of running docker.

## Install docker
```
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker
```

## Download kCTF
```
sudo apt-get install -y subversion
svn checkout https://github.com/google/google-ctf/trunk/infrastructure/kubernetes
PATH=$PATH:$PWD/kubernetes/bin
```

## Enable and build nsjail
```
echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone
sudo service procps restart
sudo mkdir -p /sys/fs/cgroup/memory/NSJAIL
sudo mkdir -p /sys/fs/cgroup/pids/NSJAIL
sudo mkdir -p /sys/fs/cgroup/cpu/NSJAIL
sudo chmod o+w /sys/fs/cgroup/*/NSJAIL
```

## Setup basic demo challenge
```
kctf-setup-chal-dir $(mktemp -d)
kctf-chal-create test-1
kctf-chal-test-docker test-1
```

## Test connecting to the challenge
```
sudo apt-get install -y netcat
nc 127.0.0.1 1337
```
