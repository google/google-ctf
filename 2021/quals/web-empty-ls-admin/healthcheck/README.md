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

# Healthcheck

kCTF checks the health of challenges by accessing the healthcheck via
http://host:45281/healthz which needs to return either 200 ok or an error
depending on the status of the challenge.

The default healthcheck consists of:
* a loop that repeatedly calls a python script and writes the status to a file
* a webserver that checks the file and serves /healthz
* the actual healthcheck code using pwntools for convenience

To modify it, you will likely only have to change the script in healthcheck.py.
You can test if the challenge replies as expected or better add a full example
solution that will try to get the flag from the challenge.
