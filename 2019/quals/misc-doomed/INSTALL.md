# License of this file

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Memory

Memory is a fun and secure web game. Players who beat it get a little prize.

Memory is written in go because go is memory-safe, which is very important for
a game like Memory with strict safety requirements.

## Build/Run

First install go. Version 1.12 is recommended, but 1.11 probably works.

Create the `flag.txt` file.

There are 2 ways to build/run: go modules, and GOPATH. Modules is the easiest
assuming you don't want to deploy to App Engine flex.

### Modules

Make sure whatever directory you're currently in is not a subdirectory of
`$GOPATH` (which is treated as `$HOME/go` if empty). Put the contents of the zip
file in a directory named `memory`, and enter that directory.

Initialize the module (this creates a `go.mod` file):

    go mod init memory

The next steps (`build`/`run`) will automatically install the necessary
dependencies using modules. See here for more details
https://github.com/golang/go/wiki/Modules#quick-start .

Run with visible binary

    go build
    ./memory

Run with non-visible binary

    go run memory

### GOPATH

Go to your `$GOPATH/src` directory. If `$GOPATH` is empty, it is assumed to be
`$HOME/go` so the full path then would be `$HOME/go/src` .

Put the contents of the zip file in a directory named `memory` there. So now for
example there is a file `$GOPATH/src/memory/game/game.go` .
Ensure there are no `go.mod` and `go.sum` files.

Install the dependencies

    go get -u -v github.com/gorilla/websocket golang.org/x/crypto/argon2

Run with visible binary

    go build
    ./memory

Run with non-visible binary

    go run memory

## Deploy to App Engine flex

First do the GOPATH install method. Then deploy it. You can change the project
with the `--project` flag.

    gcloud app deploy

## flag.txt

The `memory` binary assumes that in the current directory there is a file named
`flag.txt` that doesn't contain a newline character. Create it.

    echo -n 'CTF{something}' > flag.txt
