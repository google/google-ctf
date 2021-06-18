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

const BaseService = require("./base_service.js")

class AuthService extends BaseService {
  playersDB

  constructor(playersDB, gameService) {
    super()
    this.playersDB = playersDB
    this.gameService = gameService
  }

  onOpen(pc) {
    pc.send({
      type: "plzAuth"
    })
  }

  loginPlayer(pc, playerInfo, observer) {
    pc.isAuthenticated = true
    pc.username = playerInfo.username
    pc.displayName = playerInfo.name
    pc.observer = observer
    if (playerInfo.frameSet) {
      pc.frameSet = playerInfo.frameSet
    }
    pc.playerInfo = playerInfo
    if (observer) {
      pc.nextTick = 0
    }
    pc.send({ type: "authOK", fastToken: playerInfo._fastToken })
    pc.attachService(this.gameService)
  }

  onMessage(pc, data) {
    // TODO: where do we put protocol validator?
    switch (data.type) {
      case "fastAuth": {
        const playerInfo = this.playersDB.loginFast(data.token)
        if (playerInfo) {
          this.loginPlayer(pc, playerInfo, data.observer)
        } else {
          pc.send({ type: "plzAuthFull" })
        }
      }
      break;

      case "fullAuth": {
        const playerInfo = this.playersDB.login(data.username, data.password)
        if (playerInfo) {
          this.loginPlayer(pc, playerInfo, data.observer)
        } else {
          pc.send({ type: "authFail" })
          pc.send({ type: "plzAuthFull" })
        }
      }
      break;
    }
  }

  onClose(pc) {
  }
}

module.exports = AuthService
