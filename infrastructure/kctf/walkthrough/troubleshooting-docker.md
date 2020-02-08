# Troubleshooting

Users are reporting a challenge is down, when you connect, you see nothing. Let's troubleshoot.

## Setup first / REPRODUCING

To play this game, we need to simulate a broken challenge, so we have one in samples. Run:
```
kctf-setup-chal-dir $PWD/samples
```

This will setup the samples directory as a challenge directory, and now let's go to the challenge directory.
```
cd samples/troubleshooting
```

Now here, we want to test in docker:
```
make test-docker
```

That will output something like this:
```
CONTAINER ID        IMAGE                       COMMAND                  CREATED             STATUS                  PORTS                     NAMES
81d06c71f6b5        kctf-chal-troubleshooting   "/bin/sh -c '/usr/bi…"   1 second ago        Up Less than a second   0.0.0.0:32780->1337/tcp   unruffled_payne
```

Notice that there's a PORTS column that tells you that the port 32780 in your local machine is mapped to the port 1337 inside the container.

Let's connect to the local port (change 32780 with the port in the command).
```
nc 0 32780
```

And.. it doesnt work indeed, if you type anything, nothing will happen.

## Searching second / DEBUGGING

Let's look at the docker logs:
```
docker logs $(docker ps -q -f ancestor=kctf-chal-troubleshooting)
```

We see an error:
```
[E][2020-02-02T20:20:02+0200][1] void subproc::subprocNewProc(nsjconf_t*, int, int, int, int)():204 execve('/bin/sh') failed: No such file or directory
```

Great, now we have a thread to pull. Sounds like when doing execve on /bin/sh we are failing to run anything.

Let's get a shell to the task:
```
docker exec -it $(docker ps -q -f ancestor=kctf-chal-troubleshooting) bash
```
That worked, so let's look into nsjail.

```
ps aux
```

And by running that you can see that it seems like nsjail is running.. let's try to run it again, but in standalone mode:

```
/usr/bin/nsjail --config /config/nsjail.cfg -Mo
```

Alright, we get the same error. Let's try to run nsjail using one of the examples from the documentation:

```
nsjail -Mo --chroot / -- /bin/echo "ABC"
```

OK, that worked. Let's try to run sh instead of echo.

```
nsjail -Mo --chroot / -- /bin/sh
```

That worked. Now let's exit nsjail, and run it from the container again, but with --config:

```
nsjail --config /config/nsjail.cfg -Mo --chroot / -- /bin/sh
```

That works. Now let's try to just run the default command:

```
/usr/bin/stdbuf: failed to run command '/usr/bin/maybe_pow.sh': No such file or directory
```

Looks like maybe_pow.sh is not there. Let's see where it's supposed to be.

```
$ grep -r maybe_pow.sh *
base/nsjail-docker/Dockerfile:COPY files/proof_of_work/maybe_pow.sh /chroot/usr/bin/
base/challenge-skeleton/config/nsjail.cfg:    arg: "exec /usr/bin/stdbuf -i0 -o0 -e0  /usr/bin/maybe_pow.sh /home/user/chal"
```

Looks like it's defined in base/nsjail-docker/Dockerfile, it should be in /chroot/usr/bin, lets see if it's in docker

```
ls /chroot/usr/bin/maybe_pow.sh
```

It is there, so apparently nsjail isn't configured to run under the chroot, let's add --chroot /chroot to the Dockerfile CMD, after updating the code, it should look like this:
```
CMD /usr/bin/k8s_nsjail_setup.sh && exec setpriv --init-groups --reset-env --reuid user --regid user --inh-caps=-all /usr/bin/nsjail --config /config/nsjail.cfg --chroot /chroot
```

Note that there's a new --chroot /chroot command at the end.

## Was that it?

Let's run make test-docker again and connect one more time.
```
/usr/bin/maybe_pow.sh: line 13: /home/user/chal: Permission denied
/usr/bin/maybe_pow.sh: line 13: exec: /home/user/chal: cannot execute: Permission denied
```

Now we get new errors, but these look easier to fix, let's just add a chmod +x in the Dockerfile (before CMD):
```
RUN chmod +x /chroot/home/user/chal
```

And now let's just connect again.

```
/home/user/chal: line 5: ./shell: No such file or directory
```

It seems like there's an error in /home/user/chal, let's modify the challenge to tell us what's going on. For this let's add `ls -lah .` to files/chal and redeploy and connect again:

This will show we are in root, not in /home/user/chal. It seems like we are in the wrong directory, let's fix it by cd'ing to the right directory.

```
cd home/user
```

And rebuild and reconnect:

```
sh: 1: bash-i: not found
```

OK, new error.. This one looks like we forgot a space somewhere.. let's look where this is used:

```
$ grep -r bash-i *
Binary file files/shell matches
src/shell.c:  system("bash-i");
```

OK, seems like src/shell.c has a typo, let's fix it and add space to bash-i, and then rebuild and connect again..
```
Handling connection for 37115
launching shell...
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
user@NSJAIL:/home/user$ exit
```

and it works now. Success!

## Conclusion

Testing locally with `make test-docker` is the easiest and fastest way to troubleshoot challenges, and you don't need to know much besides some basic docker commands presented here.
