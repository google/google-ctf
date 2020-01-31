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

## Setup nsjail configuration
```
(echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone) || (echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/00-local-userns.conf) 2>&1
sudo service procps restart
sudo mkdir -p /sys/fs/cgroup/memory/NSJAIL /sys/fs/cgroup/pids/NSJAIL /sys/fs/cgroup/cpu/NSJAIL
sudo chmod o+w /sys/fs/cgroup/*/NSJAIL
```

## Create basic demo challenge
```
kctf-setup-chal-dir $(mktemp -d)
kctf-chal-create test-1
```

## Test connecting to the challenge
```
kctf-chal-test-docker test-1
sudo apt-get install -y netcat
nc 127.0.0.1 1337
```

## Debug failures

### Errors building the docker images
In some cases, docker might fail to run because of network errors. Check if you have this error
```
 ---> [Warning] IPv4 forwarding is disabled. Networking will not work.
```
If so, then you have to enable ipv4 forwarding, by running:
```
echo net.ipv4.ip_forward=1 | sudo tee -a /etc/sysctl.conf
```
And since this probably made docker cache an invalid `apt-get update`, you will also have to run `docker system prune -a` before running the `kctf-chal-test-docker` command again.

### Errors connecting to the challenge
If you can't connect, type ```docker ps -a``` and look for the last ran container, and then run ```docker logs CONTAINER_NAME``` replacing CONTAINER_NAME with the name of the last ran container.

That will output the logs of the last time the container ran, if you see errors like:
```
[W][2020-01-31T19:49:47+0000][1] bool cgroup::createCgroup(const string&, pid_t)():43 mkdir('/cgroup/memory/NSJAIL/NSJAIL.10', 0700) failed: No such file or directory
```
That probably means the NSJAIL cgroup directories didn't get created in the nsjail setup step above, try running the [setup nsjail configuration](#setup-nsjail-configuration) step again and then run `kctf-chal-test-docker` again.

If the error is like this:
```
[E][2020-01-31T20:16:39+0000][1] bool subproc::runChild(nsjconf_t*, int, int, int)():459 nsjail tried to use the CLONE_NEWCGROUP clone flag, which is supported under kernel versions >= 4.6 only. Try disabling this flag: Operation not permitted
[E][2020-01-31T20:16:39+0000][1] bool subproc::runChild(nsjconf_t*, int, int, int)():464 clone(flags=CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET|SIGCHLD) failed. You probably need root privileges if your system doesn't support CLONE_NEWUSER. Alternatively, you might want to recompile your kernel with support for namespaces or check the current value of the kernel.unprivileged_userns_clone sysctl: Operation not permitted
```
That probably means that unprivileged user namespaces are not enabled, you can fix this by running the [setup nsjail configuration](#setup-nsjail-configuration) step again and then try connecting through netcat again.

### Errors inside the challenge
If you see errors like these:
```
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
```

That's normal, just ignore it. You should still get a shell afterwards.
