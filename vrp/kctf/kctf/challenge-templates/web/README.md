# Quickstart guide to writing a challenge

The basic steps when preparing a challenge are:

* A Docker image is built from the `challenge` directory. For the simplest challenges, replacing `challenge/chal.c` is sufficient.
* Edit `challenge/Dockerfile` to change the commandline or the files you want to include.
* To try the challenge locally, you will need to
  * create a a local cluster with `kctf cluster create --type kind --start $configname`
  * and then deploy the challenge with `kctf chal start`
* To access the challenge, create a port forward with `kctf chal debug port-forward` and connect to it via `nc localhost PORT` using the printed port.
* Check out `kctf chal <tab>` for more commands.

## Sandboxing

Sandboxing is only necessary for challenges that give players RCE-type of access. If a challenge does not provide such access, then it is reasonable to just use a normal HTTP server out of the box listening on port 1337, without any additonal sandboxing.

For challenges that give users RCE-level access, it is then necessary to sandbox every player. In order to make that possible, kCTF provides two ways to sandbox a web server:
 1. **CGI-sandbox**: You can configure PHP (or any other CGI) to be sandboxed.
 2. **Proxy sandbox**: You can configure an HTTP server that sandboxes every HTTP request.

A Proxy sandbox is a bit expensive, it starts an HTTP server on every TCP connection, hence it is a bit slow. A CGI sandbox is cheaper, and it just calls the normal CGI endpoint but with nsjail.

The template challenge has an example of both (NodeJS running as a proxy, and PHP running as CGI). It is recommended that static resources are served with only Apache, as to save CPU and RAM. This can be accomplished by configuring apache to redirect certain sub-paths to the sandboxed web server, but to serve directly all other paths.

## Directory layout

The following files/directories are available:

### /challenge.yaml

`challenge.yaml` is the main configuration file. You can use it to change
settings like the name and namespace of the challenge, the exposed ports, the
proof-of-work difficulty etc.
For documentation on the available fields, you can run `kubectl explain challenge` and
`kubectl explain challenge.spec`.

If you would like to have a shared directory (for sessions, or uploads), you can mount it using:


```yaml
spec:
  persistentVolumeClaims:
  - $PUT_THE_NAME_OF_THE_CHALLENGE_HERE
  podTemplate:
    template:
      spec:
        containers:
        - name: challenge
          volumeMounts:
          - name: gcsfuse
            subPath: sessions # this this a folder inside volume
            mountPath: /mnt/disks/sessions
          - name: gcsfuse
            subPath: uploads
            mountPath: /mnt/disks/uploads
        volumes:
        - name: gcsfuse
          persistentVolumeClaim:
            claimName: $PUT_THE_NAME_OF_THE_CHALLENGE_HERE
```

This will mount a file across all challenges in that directory. You can test this setup on a remote cluster using the PHP/CGI sandbox.

### /challenge

The `challenge` directory contains a Dockerfile that describes the challenge and
any challenge files. You can use the Dockerfile to build your challenge as well
if required.

### /healthcheck

The `healthcheck` directory is optional. If you don't want to write a healthcheck, feel free to delete it. However, we strongly recommend that you implement a healthcheck :).

We provide a basic healthcheck skeleton that uses pwntools to implement the
healthcheck code. The only requirement is that the healthcheck replies to GET
requests to http://$host:45281/healthz with either a success or an error status
code.

In most cases, you will only have to modify `healthcheck/healthcheck.py`.

## API contract

Ensure your setup fulfills the following requirements to ensure it works with kCTF:

* Verify `kctf_setup` is used as the first command in the CMD instruction of your `challenge/Dockerfile`.
* You can do pretty much whatever you want in the `challenge` directory but:
* We strongly recommend using nsjail in all challenges. While nsjail is already installed, you need to configure it in `challenge/nsjail.cfg`. For more information on nsjail, see the [official website](https://nsjail.dev/).
* Your challenge receives connections on port 1337. The port can be changed in `challenge.yaml`.
* The healthcheck directory is optional.
  * If it exists, the image should run a webserver on port 45281 and respond to `/healthz` requests.
