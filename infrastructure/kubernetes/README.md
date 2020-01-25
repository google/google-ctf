# Walkthrough
[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.png)](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/google/google-ctf&tutorial=infrastructure/kubernetes/walkthrough.md)

# Errors
 - If you can't connect to port 1 of the IP address, that's probably because the challenge didnt deploy. See [Debugging deployment](#debugging-deployment) below.
 - If you see `Unable to connect to the server: dial tcp ...:443: i/o timeout`, that's probably because there no cluster was created. Run `kctf-cluster-create`.
 - If you see `ERROR: (gcloud.dns.record-sets.transaction.start) HTTPError 404: The 'parameters.managedZone' resource named '...-dns-zone' does not exist.`, that's probably because the DNS zone hasn't yet been created. Run `kctf-setup-dns`.

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
