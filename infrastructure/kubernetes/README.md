# Codelab

1. Go to https://console.developers.google.com/apis/api/compute.googleapis.com/overview and enable compute + billing.
1. Modify `cluster_vars` to point to the right version of Kubernetes, and the right GCP project name.
1. Run `./create_cluster.sh` - this only needs to be done once per CTF.
1. Modify `challenge-skeleton/challenge.yaml` and modify the image path to point to the right project name.
1. Run `./create_image.sh challenge-skeleton` - this only needs to be done if you want to build the challenge, but not to deploy it.
1. Run `./deploy.sh challenge-skeleton` - this builds and deploys the challenge, but doesn't expose it to the internet.
1. Run `./expose.sh challenge-skeleton` - this exposes the challenge to the internet (does not build it).
1. Run `nc $theip 1` - this connects you to the challenge.
1. Edit `pow.yaml` and change the 0 to 1, then run `./update.sh challenge-skeleton` - this enables the proof of work.
1. Run `nc $theip 1` - this connects you to the challenge with a proof of work in front.
1. Run `./kill_challenge.sh challenge-skeleton` - this kills the challenge.
1. Run `nc $theip 1` - this will not work anymore.

## Future Work
 - Automate the setup of `cluster_vars`, and have a command that generates `challenge.yaml`.
 - Cleanup the proof of work to point somewhere that isn't the ccc website.

## Budgetting
 - Calculate the resources and the amount of budget assuming 100% consumption.
 - Add a budget alert at 25% budget, 50% budget, 75% budget and 100% of budget.
 - Plan for the CTF to last 50% longer than it will, increase proof of work on challenges using too much CPU.

# Errors
 - If you forget to update the kubernetes version in `cluster_vars`, you get an error saying that it's not supported.
 - If you forget to update the project name in `challenge-skeleton/challenge.yaml`, you get an error referencing `gctf-k8s`
 - If you can't connect to port 1 of the IP address, that's probably because the challenge didnt deploy.

# Debugging
 - Go to https://console.cloud.google.com/kubernetes/list and click on services.
 - Look for the challenge, and click on it to reach the kubernetes service page for the challenge.

## Debugging deployment
 - From the kubernetes service page for the challenge.
 - Under overview, look for the "Stackdriver logs" row and click on the link.

## Debugging challenge
 - From the kubernetes service page for the challenge.
 - Under overview, look for "Service Pods", click on one of them.
 - On the top right corner there's a "KUBECTL" button, click on it, and then on "Exec" and then on the task name.
 - On the Cloud Shell, modify the end of command from `-- ls` to `-it -- /bin/bash` and run `cd home/user`.
