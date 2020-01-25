# Walkthrough
[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.png)](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/google/google-ctf&tutorial=infrastructure/kubernetes/walkthrough.md)

# Errors
 - If you can't connect to port 1 of the IP address, that's probably because the challenge didnt deploy. See [Debugging deployment](#debugging-deployment) below.
 - If you see `Unable to connect to the server: dial tcp ...:443: i/o timeout`, that's probably because there no cluster was created. Run `kctf-cluster-create`.
 - If you see `ERROR: (gcloud.dns.record-sets.transaction.start) HTTPError 404: The 'parameters.managedZone' resource named '...-dns-zone' does not exist.`, that's probably because the DNS zone hasn't yet been created. Run `kctf-setup-dns`.

# Debugging
 - Use the `kctf-chal-status` command to inspect the status of the challenge.
   - If the challenge is not deployed, see [Debugging deployment](#debugging-deployment) below.
   - If the challenge is deployed but still doesn't work see [Debugging challenge](#debugging-challenge) below.

## Debugging deployment
 - Use the `kctf-chal-logs challenge_name` command to see the logs of the challenge deployment.

## Debugging challenge
 - Use the `kctf-chal-shell challenge_name` command to shell into the challenge and inspect it.
