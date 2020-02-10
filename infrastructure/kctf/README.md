# Walkthrough
[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.png)](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/google/google-ctf&tutorial=infrastructure/kctf/walkthrough/google-cloud.md)

# Prerequisites

* [gcloud](https://cloud.google.com/sdk/install)
* [docker](https://docs.docker.com/install/)
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) 1.17+

# Introduction

If you want to read what is kCTF take a look at [kCTF in 8 minutes](introduction.md). A quick 8 minutes summary of what is kCTF and how it interacts with Kubernetes.

# DNS Support
If you point a domain or subdomain to Google Cloud DNS, you can use `kctf-setup-dns` and `kctf-chal-dns` to map *challenge_name.yourdomain.com* to your challenge.

1. Make sure to configure the subdomain in `kctf-setup-config-create`. If you type *foo.example.com*, then the challenges will be deployed on *challenge_name.foo.example.com*.
1. After that, run `kctf-setup-dns` to create the DNS zone in Google Cloud DNS.
1. Make sure to point the subdomain to Google Cloud DNS. This requires [adding an NS record on your name server](https://cloud.google.com/dns/docs/update-name-servers).
1. After you run `kctf-chal-expose challenge_name` to expose your challenge, you will also need to run `kctf-chal-dns challenge_name` to setup the subdomain.
