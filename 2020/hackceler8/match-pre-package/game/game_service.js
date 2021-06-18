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
const gameState = require("./common/game-state")
const ChallengeConnector = require("./challenge_connector.js")

// Important: BackendObjects may be influenced by rejected state changes - this
// is by design and has to be accounted for in the code.
class BackendObjects {
  username = null
  gameService = null
  map = null
  challenges = []
  challengeIndex = new Map()
  connectors = {}

  lastFlagPrecheck = Date.now()

  constructor(username, gameService, map, config) {
    this.username = username
    this.gameService = gameService
    this.map = map
    this.config = config

    config.challenges.forEach(chal => {

      const challengeObj = {
          id: chal.id,
          flag: chal.flag
      }

      this.challenges.push(challengeObj)
      this.challengeIndex.set(chal.id, challengeObj)

      if (chal.hasOwnProperty("host")) {
        this.connectors[chal.id] = new ChallengeConnector(
            chal.host, chal.port, {
            connecting: () => {
              this.terminalSendToPlayer(chal.id, "connecting")
            },
            connect: () => {
              this.terminalSendToPlayer(chal.id, "connect")
            },
            data: data => {
              this.terminalSendToPlayer(chal.id, "data", data)
            },
            error: () => {
              this.terminalSendToPlayer(chal.id, "error")
            },
            disconnect: () => {
              this.terminalSendToPlayer(chal.id, "disconnect")
            }
          }
        )
      }
    })
  }

  terminalSendToPlayer(challengeID, eventType, data=null) {
    this.gameService.sendMessage(this.username, {
      type: "terminal",
      challengeID: challengeID,
      eventType: eventType,
      data: data ? data.toString("hex") : null
    })
  }
}

class GameService extends BaseService {
  stateManagers = {}
  playerConnections = null
  config = null

  constructor(gameMap) {
    super()
    this.playerConnections = new Map()
    this.gameMap = gameMap
  }

  setConfig(config) {
    this.config = config
  }

  prepareStateManager(pc) {
    if (this.stateManagers.hasOwnProperty(pc.username)) {
      // State manager is already there.
      return
    }

    const backendObjects = new BackendObjects(
        pc.username, this, this.gameMap, this.config
    )
    const initialState = new gameState.GameState(this.gameMap, backendObjects)
    initialState.initialize()

    const stateManager = new gameState.GameStateManager(backendObjects)
    stateManager.setInitialState(initialState)
    this.stateManagers[pc.username] = stateManager
  }

  onOpen(pc) {
    // Replace old connection with new one.
    this.removePlayerConnection(pc.username)
    this.playerConnections.set(pc.username, pc)

    console.log("Player (re)connected:", pc.username)

    this.prepareStateManager(pc)
    this.stateManagers[pc.username].restartConnection()

    pc.send({
      type: "map",
      map: this.gameMap.getUnprocessed()
    })
  }

  sendMessage(username, data) {
    const pc = this.playerConnections.get(username)
    if (!pc) {
      // Player is not connected. Tough luck.
      return
    }

    pc.send(data)
  }

  onMessage(pc, data) {
    // TODO: where do we put protocol validator?

    const stateManager = this.stateManagers[pc.username]

    switch (data.type) {
      case "mapReady": {
        pc.send({
          type: "startState",
          state: stateManager.getState(),
          volatile: "volatile state goes here, like terminals and stuff"
        })
        break
      }

      case "ticks": {
        // TODO: send to verifier
        if (!stateManager.processNewChanges(data.changes)) {
          // TODO: apply 5000 ms ban on player.
          pc.send({
            type: "stateError",
            timeout: 5000  // 5000ms ban. TODO: constant
          })
          pc.close()
        }

        break
      }

      case "precheckFlag": {
        // Rate limit.
        const MINIMUM_WAIT_TIME = 100  // Milliseconds.
        const BRUTE_BAN = 2000 // Milliseconds.
        const backendObject = stateManager.backendObject
        const now = Date.now()

        const timeDiff = now - backendObject.lastFlagPrecheck
        if (timeDiff < 0) {  // Ban in effect.
          // Go away.
          break
        }

        backendObject.lastFlagPrecheck = now

        if (timeDiff < MINIMUM_WAIT_TIME) {
          // Go away.
          backendObject.lastFlagPrecheck = now + BRUTE_BAN
          console.warn(
              `Flag brute force detected. Banning for ${BRUTE_BAN} ms.`
          )
          break
        }

        // Check the flag.
        const challenge = backendObject.challengeIndex.get(
            data.challengeID
        )
        if (!challenge) {
          // Meh.
          break
        }

        const correctHash = challenge.flag

        const hash = crypto.createHash("sha256")
        hash.update(data.flag)
        const flagHash = hash.digest("hex")

        pc.send({
          type: "precheckFlagResponse",
          challengeID: data.challengeID,
          flag: data.flag,  // Send the same flag back.
          result: (flagHash === correctHash)
        })

        break
      }
    }
  }

  onClose(pc) {
    this.removePlayerConnection(pc.username)
    console.log("Player disconnected:", pc.username)
  }

  removePlayerConnection(username) {
    const pc = this.playerConnections.get(username)
    if (!pc) {
      return
    }

    pc.close()

    this.playerConnections.delete(username)
  }
}

module.exports = GameService
