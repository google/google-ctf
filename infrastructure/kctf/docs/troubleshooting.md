# Troubleshooting

Users are reporting a challenge is down, the author is offline, and you don't know how long the challenge has been broken. The challenge had no healthcheck configured, and there's no documentation. Someone forgot to test the task. A nightmare come true.

This guide will show you how to troubleshoot a broken challenge assuming you don't know how the challenge works.

Here the commands will use `kctf-chal-troubleshooting` as the name of the broken challenge as an example, replace that with the actual name of the challenge.

This guide will take you through troubleshooting a task [in docker](#troubleshooting-with-docker), then [in a local cluster](#troubleshooting-with-kubernetes), and then [remotely](#troubleshooting-remotely).

## Troubleshooting with Docker

### Building and running Docker

A good place to start is to check if the Docker image works. It could happen that an author made a small change to a Dockerfile which broke the task. So if the challenge doesn't even start, that would be a good indication that something is broken.

To build the docker image you can run:
```
make docker
```

This will output any errors when *building* the image, but it won't actually be run, if you would like to run the image, you can run:

```
make test-docker
```

That will output something like this near the end:
```
CONTAINER ID        IMAGE                       COMMAND                  CREATED             STATUS                  PORTS                     NAMES
81d06c71f6b5        kctf-chal-troubleshooting   "/bin/sh -c '/usr/bi…"   1 second ago        Up Less than a second   0.0.0.0:32780->1337/tcp   unruffled_payne
```

Notice that there's a PORTS column that tells you that the port 32780 in your local machine is mapped to the port 1337 inside the container. The challenge should work if you connect to it now, so you should try to connect to the local port (change 32780 with the port in the command)

```
nc localhost 32780
```

If the challenge is very broken, it won't work, if you type anything, nothing will happen. Another possible way in which the challenge could be broken, is if there was an error running the command, in which case connecting to the challenge will also not work (it would just exit).

You can actually check if the challenge is still running a few seconds after starting it, by just running:
```
docker ps -f ancestor=kctf-chal-troubleshooting
```

If you don't see the challenge running anymore, that's a good indication that the task failed to even start. If the challenge is still running, but connecting to it fails, then the challenge started properly but there's some runtime error.

Either way, the next step would be to read the docker logs.

### Looking at the logs

If the challenge builds, but running it doesn't work, the best thing to try is to read the docker logs. To get the the docker logs, run:
```
docker logs $(docker ps -q -f ancestor=kctf-chal-troubleshooting)
```

If the challenge is a pwnable, you might see an error formatted like this:
```
[E][2020-02-02T20:20:02+0200][1] void subproc::subprocNewProc(nsjconf_t*, int, int, int, int)():204 execve('/bin/sh') failed: No such file or directory
```

That's an NsJail error. In this case, it is complaining that `/bin/sh` failed and gave the error *"No such file or directory"*.

If the challenge is based on the `apache-php` example, you will see apache access/error logs instead, but either way, to continue to debug you would need to find out what is going on inside the challenge.

### Shell into the docker image

To continue debugging, can get a "shell" into the container with `docker exec`, to do this run:
```
docker exec -it $(docker ps -q -f ancestor=kctf-chal-troubleshooting) bash
```

Once inside you can inspect the environment in which the challenge is running. For example, you can list the current processes:
```
ps aux
```

This way you can find out what is currently running on the task, but you could also find this out by reading the Dockerfile and checking the `CMD` that is configured there.

Here you can also inspect other logs (if any) as well as check the permissions on the filesystem. The next step in debugging would be to run the command on the shell directly and see if you can get new information.

The next troubleshooting step is to find where NsJail is being called. For pwnables, NsJail will be running directly as the listening service, and for web tasks, it would run as a CGI script when PHP files are executed.

### Debugging NsJail

The configuration for NsJail will usually live in /config. You will want to run nsjail again with the same command that Docker attempted, but for testing. NsJail supports overriding configuration via command line arguments added after the `--config` flag. If NsJail is configured to work in "listening" mode (eg, listening on a port), then you can override that to run in `run_once` mode by adding the flag `-Mo`:
```
/usr/bin/nsjail --config /config/nsjail.cfg -Mo
```

This should trigger the same error as the one found in `docker logs` from the previous step, however, now you can enable more verbose options if you run:
```
/usr/bin/nsjail --config /config/nsjail.cfg -Mo -v
```

This should output more errors, that should provide you with more details about what went wrong.

## Troubleshooting with Kubernetes

If everything works in docker, the problem might be higher up (in Kubernetes). The first step to debug this would be to check if the challenge works in a local cluster. Follow the instructions [here](local-testing.md#running-the-challenge-in-kubernetes) for getting the task running in KIND.

### Basic commands

Once the local cluster is running, you can follow similar steps as above for debugging.

For getting the status of the challenge you can run:
```
kubectl get deployment/kctf-chal-troubleshooting
```

For reading execution logs, you can run:
```
kubectl logs deployment/kctf-chal-troubleshooting -c challenge
```

For obtaining a shell into a pod, you can run:
```
kubectl exec -it deployment/kctf-chal-troubleshooting -c challenge
```

However, there are a few more commands for debugging Kubernetes-specific errors.

### Inspecting a Kubernetes Deployment

Basic understanding of Kubernetes would be useful (such as the [kCTF in 8 minutes](introduction.md) document), but this guide should be intuitive enough to understand roughly what is happening even without that.

The most common way to troubleshoot will be with the `kubectl describe` command. This command will tell you everything kubernetes knows about a challenge. You should start by describing the "deployment" by running:
```
kubectl describe deployment/kctf-chal-troubleshooting
```

The most interesting parts of this command will be the:
 - *Status* and *Reason*
 - Events

If the deployment worked, you should see in Events (at the end) that the challenge tried to create one or two "Pods" (you can think of a pod as a replica). Otherwise, the *Status* will tell you that it wasn't able to for some *Reason*. This usually means the configuration files were manually modified by the author of the task, so it's a good moment to investigate the change history for the files below the `k8s` directory of the challenge directory.

### Looking into the Pods

The next step is to look into the replicas of the challenge (the pods), you can list the pods for a specific challenge by running:
```
kubectl get pods --selector=app=kctf-chal-troubleshooting
```

This should tell you the status of the task, a healthy challenge should look like this:
```
NAME                         READY   STATUS    RESTARTS   AGE
apache-php-9877d8b7c-k89zw   2/2     Running   0          24h
apache-php-9877d8b7c-t2p4k   2/2     Running   0          24h
```

Notice that READY says 2/2, which means 2 out of 2 containers are ready. If there's an error you might see RESTARTS to have a number larger than 0, or READY to say 1/2 or 0/2.

To debug this, you then run:
```
kubectl describe pods --selector=app=kctf-chal-troubleshooting
```

This will describe the pod, of interest will be (similarly to deployment) the fields:
 - *Status* and *Reason*
 - Events
 - *State* (per container)

A healthy challenge should have as Status and State running. Anything else will explain why under *Reason*.

If the *Reason* doesn't make sense, you can find more information under *Events*. Ideally, the last line of *Events* should be:
```
Normal   Created          71m             ...     Created container challenge
```

Otherwise, the Event will explain what the problem was.

## Troubleshooting remotely

Get your hat and your boots ready, because you are gonna be testing on production! This is probably the last resort, and the most likely to not fix any problems (and rather introduce new ones), but this is an unavoidable step as often errors are easier to debug in production.

### Basic troubleshooting

Similarly to docker and kubectl commands, there are similar commands for kCTF.

To get the status of the challenge, you can run:
```
make status
```

To shell into a challenge, you can run:
```
make ssh
```

To shell into the healtchcheck, you can run:
```
make healthcheck-ssh
```

To obtain remote logs, you can run:
```
make logs
```

In addition, you can run any kubectl command under the kCTF cluter by configuring kubectl to use the kubeconfig of the remote cluster. You can setup an alias to do this if you run:
```
alias kctf-kubectl="kubectl --kubeconfig=${HOME}/.config/kctf/kube.conf"
```

### Restarting or redeploying

A good first step is to just restart the challenge. This can be done if you just run:
```
kctf-kubectl rollout restart deployment/kctf-chal-troubleshooting
```

To make kubernetes automatically restart flaky challenges, you should have a healthcheck. To redeploy the challenge (for example, if the challenge works well locally in a local cluster), you can run:
```
make start
```

This will deploy the local challenge to the remote cluster, and to undo a bad rollout temporarily, you can run:
```
kubectl rollout undo deployment/kctf-chal-troubleshooting
```

## Conclusion

Testing locally with `make test-docker` is the easiest and fastest way to troubleshoot challenges, and you don't need to know much besides some basic docker commands presented here.

Troubleshooting with kubernetes requires more setup, and should be rare (only relevant if the author made changes to the kubernetes setup, or there's a bug in kCTF).

Troubleshooting remotely is trivial, although it runs the risk of the user leaving the remote state in an inconsistent state, however it's a good last-resort.
