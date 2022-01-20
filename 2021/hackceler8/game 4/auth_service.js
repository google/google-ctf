// Copyright 2022 Google LLC
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
    const continueAble = this.gameService.stateManagers.hasOwnProperty(pc.username)
    pc.send({ type: "authOK", fastToken: playerInfo._fastToken })
    if (pc.observer) {
      this.onMessage(pc, {type: "continueGame"})
    } else {
      pc.send({ type: "savegames", "savegameMeta": this.playersDB.savegameMeta(playerInfo.username), "continueAble": continueAble})
    }
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

      case "newGame": {
        if (this.gameService.stateManagers.hasOwnProperty(pc.username)) {
          this.gameService.stateManagers[pc.username].resetToInitialState()
        }

        this.gameService.prepareStateManager(pc)
        pc.attachService(this.gameService)
      }
      break;

      case "continueGame": {
        this.gameService.prepareStateManager(pc)
        pc.attachService(this.gameService)
      }
      break;

      case "loadGame": {
        const name = data.name
        const save = this.playersDB.loadSavegame(pc.username, name)
        if (save === undefined) {
          console.error("Failed to find save", name)
          pc.send({ type: "loadFail", message: "Could not load save " + name})
          break;
        }
        this.gameService.prepareStateManager(pc)
        this.gameService.stateManagers[pc.username].setCurrentState(save.state, save.is_backup === true)
        console.log("Loaded save", name)
        pc.attachService(this.gameService)
      }
      break;

    }
  }

  onClose(pc) {
  }
}

module.exports = AuthService
