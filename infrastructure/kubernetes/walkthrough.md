# CTF Infrastructure Walkthrough

The purpose of this walkthrough is to guide you along the way to configure the infrastructure.

## First, enable the necessary GCP features
Before we start, you need to have billing set up, and the compute API enabled. Let's do that now.
1. <walkthrough-project-billing-setup>Select a project and enable billing.</walkthrough-project-billing-setup>
1. <walkthrough-enable-apis apis="compute.googleapis.com">Enable the compute API.</walkthrough-enable-apis>

## Then, configure the project

### Go to the right directory

```
cd infrastructure/kubernetes
```

### And run the configuration script

```
./scripts/setup/config.sh
```

When prompted, type your project name:
```
{{project-id}}
```

You can use the default values for all other settings.

## And finally, create the cluster
Run the following command:
```
./scripts/cluster/create.sh
```
This only needs to be done once per CTF. A "cluster" is essentially a group of VMs with a "master" that defines what to run there.

This can take a while, you can expect to see `Creating cluster ... in ... Cluster is being health-checked...` and in a minute or so, you'll get a message telling you it's done.

While you wait, here's how the infrastructure works:
1. The CTF challenges will run inside "nsjail" (a security sandbox).
1. The contents of the nsjail sandbox will be configured in a docker container.
1. The container will be deployed using Kubernetes in a group of VMs.
1. If the VMs consume too much CPU, Kubernetes automatically deploys more VMs.
1. If the VMs consume too little CPU, Kubernetess will shut down some VMs.
1. Some very expensive challenges will probably be allocated in the same VMs as less busy challenges.

This all ensures the availability of the challenges, and saves some computing resources.

Anyway, hopefully by now the cluster is already created and we can continue with the walkthrough.

# Step 2 - Create a challenge
Now that we have a cluster setup, we need to create a challenge.

In this walkthrough, you'll learn how to create a challenge called "demo-challenge", build the docker image, deploy it to the cluster, and expose it to the internet.

You need the cluster to be created before you continue, otherwise the following commands won't work.

Click next to continue if your cluster is already created.

## First, call create_challenge.sh to copy the skeleton
Run the following command to create a challenge called "demo-challenge"
```
./scripts/challenge/new.sh demo-challenge
```

This will create a directory called `demo-challenge` under the `challenges` directory, and if you look inside of it (check files/chal for example), you'll find out the challenge configuration. The file in `files/chal` is the entry-point, that means it is executed every time there's a TCP connection. This demo challenge just runs bash, but a real challenge would instead expose a harder challenge that doesn't just give out a shell.

In the next step you'll find out how to create a docker image with the newly created challenge.

## Then, build the image
Run the following command this only needs to be done if you want to build the challenge, **but not to deploy it.**
```
./scripts/challenge/build.sh demo-challenge
```

This builds the "image", which means the docker image. Depending on how complex your challenge will be, this can be very fast or take forever.

Now to deploy it, run the following command, this builds and deploys the challenge, **but doesn't expose it to the internet.**

```
./scripts/challenge/deploy.sh demo-challenge
```

This will deploy the image to your cluster, and will soon be consuming CPU resources. The challenge will automatically scale based on traffic.

## And finally, expose it to the internet
Run the following command, this exposes the challenge to the internet **(must be deployed first)**.

```
./scripts/challenge/expose.sh demo-challenge
```

This step might take a minute, it will reserve an IP address for your challenge, and redirect traffic to your docker containers when someone connects to it. Wait for it to finish before continuing.

While you wait, you probably want to know:
 * This should only be done once the challenge is ready to be released to the public, don't do it too early or the challenge will leak.
 * The ports exposed by the challenge are configured by nsjail (see nsjail.cfg) and expose.yaml. Make sure they are kept in sync.
   * In expose.yaml, targetPort is the port that nsjail is listening on. port is the port that the external IP will listen on.

# Step 3 - Test the challenge

Now we have a challenge up and running, and we need to test it to make sure it works. In this section of the walkthrough you'll connect to the challenge, add and configure a proof of work, and update the running task.

Run the following command, this connects you to the challenge.

```
nc $(./scripts/challenge/ip.sh demo-challenge) 1
```

If all went well, you should see a shell. Now, let's add a proof of work to the task to avoid people abusing it too much.

Debugging failures here is easy, here are some things you could do if this didn't work:
1. Go to [Services in GKE](https://console.cloud.google.com/kubernetes/discovery)
1. Select demo-challenge-lb-service
1. Under *Stackdriver Logs* click on demo-challenge-deployment

If there were any errors deploying the challenge, they should be visible here.

In the next step we'll see how to edit the challenge, add a proof of work, and push an update.

## To add a proof of work, just edit pow.yaml
To add a proof of work, you just need to edit the configuration of the challenge.

Edit <walkthrough-editor-select-regex filePath="google-ctf/infrastructure/kubernetes/challenges/demo-challenge/pow.yaml" regex="0">pow.yaml</walkthrough-editor-select-regex> and change the 0 to 1.

Once that's done,  run
```
./scripts/challenge/update.sh demo-challenge
```
this enables the proof of work.

Note that this is a very weak proof of work (strength of 1), for it to be useful in a real CTF, you probably want to set it to 15, 20, or more for actually asking people to do some work. That said, for this walkthrough, let's take it easy, and leave it at 1.

Once the challenge is updated, just run:
```
nc $(./scripts/challenge/ip.sh demo-challenge) 1
```

This connects you to the challenge with a proof of work in front. Just type 1 to bypass the proof of work (told you a difficulty of 1 wasn't gonna cut it).

And that's it, now that you saw how to push a challenge and update it, let's clean up to save some resources.

## Let's just clean the challenge
This is the last step of the walkthrough, and this step you probably want to do at the end of the CTF to save resources.

Run:
```
./scripts/challenge/kill.sh demo-challenge
```

You can test this worked by running:
```
nc $(./scripts/challenge/ip.sh demo-challenge) 1
```

If all worked, that won't connect and it'll give you an error.

Thanks for doing the walkthrough, and good luck on your CTF!
