# License of this file

Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: Kegan Thorrez

# empty ls central

This is the central challenge for empty ls. It should be deployed and visible.

## Flag

The flag is configured in these configs, but the flag file itself is in
empty-ls-admin, since that's the deployment that actually has the flag.

## Service account access

I don't understand how allowing `127.0.0.0/8` allows the code to talk to
`169.254.169.254`, but it does.

### IAM

Give the service account the reCAPTCHA Enterprise > reCAPTCHA Enterprise Agent
role on the project.

Give the service account the DNS > DNS Administrator role on the project.

Those are both done with

```
gcloud projects add-iam-policy-binding \
    --role roles/recaptchaenterprise.agent your-project \
    --member "serviceAccount:empty-ls@your-project.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding your-project \
    --role roles/dns.admin \
    --member "serviceAccount:empty-ls@your-project.iam.gserviceaccount.com"
```

We better hope the challenge has no RCE or SSRF vuln. The reCAPTCHA Enterprise
role is pretty benign, attackers can't use it for much. But the DNS
Administrator role is pretty powerful, attackers can take down our DNS.

Give the kubernetes service account the ability to become this challenge's
service account:

```
gcloud iam service-accounts add-iam-policy-binding \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:your-project.svc.id.goog[default/empty-ls]"
    empty-ls@your-project.iam.gserviceaccount.com
```

Yes those are literal brackets. See

https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#authenticating\_to

Apparently this doesn't need to get checked in to piper.

## Recaptcha

This uses reCAPTCHA Enterprise. Make sure the reCAPTCHA Enterprise settings
allow whatever domain you're using.

Also make sure the static html pages as well as central.go have the correct key
id for the reCAPTCHA Enterprise key.

## GCP Project

central.go needs to specify the correct GCP project, both to get reCAPTCHA
Enterprise working as well as to get Cloud DNS working.
