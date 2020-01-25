# Walkthrough
[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.png)](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/google/google-ctf&tutorial=infrastructure/kubernetes/walkthrough.md)

# Prerequisites

* [gcloud](https://cloud.google.com/sdk/install)
* [docker](https://docs.docker.com/install/)
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) or `gcloud components install kubectl`

# DNS Support
If you point a domain or subdomain to Google Cloud DNS, you can use `kctf-setup-dns` and `kctf-chal-dns` to map *challenge_name.yourdomain.com* to your challenge.

1. Make sure to configure the subdomain in `kctf-setup-config-create`. If you type *foo.example.com*, then the challenges will be deployed on *challenge_name.foo.example.com*.
1. After that, run `kctf-setup-dns` to create the DNS zone in Google Cloud DNS.
1. Make sure to point the subdomain to Google Cloud DNS. This requires [adding an NS record on your name server](https://cloud.google.com/dns/docs/update-name-servers).
1. After you run `kctf-chal-expose challenge_name` to expose your challenge, you will also need to run `kctf-chal-dns challenge_name` to setup the subdomain.

# Debugging
 - Use the `kctf-chal-status challenge_name` command to inspect the status of the challenge.
   - If the challenge is not deployed, see [Debugging deployment](#debugging-deployment) below.
   - If the challenge is deployed but still doesn't work see [Debugging challenge](#debugging-challenge) below.

## Common errors
 - If you can't connect to port 1 of the IP address, that's probably because the challenge didnt deploy. See [Debugging deployment](#debugging-deployment) below.
 - If you see `Unable to connect to the server: dial tcp ...:443: i/o timeout`, that's probably because there no cluster was created. Run `kctf-cluster-create`.
 - If you see `ERROR: (gcloud.dns.record-sets.transaction.start) HTTPError 404: The 'parameters.managedZone' resource named '...-dns-zone' does not exist.`, that's probably because the DNS zone hasn't yet been created. Run `kctf-setup-dns`.

## Debugging deployment
 - Use the `kctf-chal-logs challenge_name` command to see the logs of the challenge deployment.

## Debugging challenge
 - Use the `kctf-chal-shell challenge_name` command to shell into the challenge and inspect it.
