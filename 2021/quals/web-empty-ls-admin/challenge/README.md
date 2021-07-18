# Liencse of this file

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

## Flag

To change the flag

```
echo -n 'CTF{new_flag}' > flag
```

Then change the flag in the configs in empty-ls, since those are the configs
with the flag. Of course a new deployment of both challenges will be needed.

## Certs and keys

The certs and keys are copied from ../../web-empty-ls/challenge . Simply run
make to copy them. The authoritative source is over there.
