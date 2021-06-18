// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"use strict"

class PlayerConnection {
  isAuthenticated
  username
  displayName
  ws
  service

  constructor(ws) {
    this.isAuthenticated = false
    this.username = null
    this.displayName = null
    this.ws = ws
    this.service = null
  }

  attachService(service) {
    this.service = service
    service.onOpen.apply(service, [this])
  }

  onMessage(m) {
    let message = null
    try {
      message = JSON.parse(m)
    } catch(e) {
      return
    }

    // TODO: some proto validator here?
    this.service.onMessage.apply(this.service, [this, message])
  }

  onClose() {
    this.service.onClose.apply(this.service, [this])
  }

  send(data) {
    if (this.ws === null) {
      return
    }

    this.ws.send(JSON.stringify(data))
  }

  close() {
    if (this.ws === null) {
      return
    }

    this.ws.close()
    this.ws = null
  }
}

module.exports = PlayerConnection
