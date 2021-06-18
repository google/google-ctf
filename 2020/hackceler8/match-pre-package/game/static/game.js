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

const game = {}

// Special functions.
function kill() {
  globals.game.auxiliaryInputQueue.push({
    type: "death",
    value: null
  })
}

// Main game class that brings together inputs, logic, visuals and server-side
// communication.
game.Game = class Game {
  static LOGIC_CHECK_INTERVAL = gameState.MS_PER_TICK / 4

  intervalHandle = null
  lastTickTime = null  // In milliseconds.
  keyStates = {}  // TODO: Change to Set()

  terminals = new Map()
  flagConsoles = new Map()

  auxiliaryInputQueue = []

  constructor() {
    window.addEventListener("keydown", (e) => {
      if (this.keyStates.hasOwnProperty(e.code)) {
        return
      }

      this.keyStates[e.code] = true
    })

    window.addEventListener("keyup", (e) => {
      delete this.keyStates[e.code]
    })

    window.addEventListener("visibilitychange", () => {
      this.keyStates = {}
    })

    window.addEventListener("blur", () => {
      this.keyStates = {}
    })
  }

  start() {
    this.recreateUIObjects()

    // Setup timeout for doing a loop iteration.
    this.lastTickTime = Date.now()
    this.intervalHandle = window.setInterval(() => {
       this.iterate()
    }, Game.LOGIC_CHECK_INTERVAL)
  }

  stop() {
    // Stop the timeout for a loop iteration.
    if (this.intervalHandle === null) {
      return
    }

    window.clearInterval(this.intervalHandle)
    this.intervalHandle = null
    this.lastTickTime = null

    this.destroyUIObjects()
    this.auxiliaryInputQueue = []
  }

  getTerminalUIObject(id) {
    return this.terminals.get(id)
  }

  getFlagConsoleUIObject(id) {
    return this.flagConsoles.get(id)
  }

  // Private.
  recreateUIObjects() {
    this.destroyUIObjects()

    Object.entries(globals.state.state.entities).forEach(e => {
      const entity = e[1]
      if (entity.type === "Terminal") {
        const id = entity.challengeID
        const terminalUI = new terminal.Terminal(id)
        terminalUI.setInputHandler(text => {
          this.auxiliaryInputQueue.push({
              type: "terminal",
              value: utils.textToHex(text)
          })
        })
        this.terminals.set(id, terminalUI)
        return
      }

      if (entity.type === "FlagConsole") {
        const id = entity.challengeID
        const flagUI = new flagConsole.FlagConsole(id)
        flagUI.setInputHandler(flag => {

          /*
          Heh guess what - SubtleCrypto is available only on 127.0.0.1 and via
          HTTPS. Since this might run over HTTP, we can't use it.
          So instead we'll just ask the server to check the flag already at this
          point (and again later when synchronizing states).

          // Since SubtleCrypto is asynchronous, we need to calculate the hash
          // here on the browser side and pass it to the game engine (since
          // game state logic cannot do asynchronous).
          crypto.subtle.digest(
              'SHA-256', utils.textEncoder.encode(flag)
          ).then(flagHash => {
            const flagHashHex = utils.uint8ArrayToHex(new Uint8Array(flagHash))
            this.auxiliaryInputQueue.push({
                type: "flag",
                value: [flag, flagHashHex]
            })
          })
          */

          main.wsSend({
            type: "precheckFlag",
            challengeID: id,
            flag: flag
          })
          // Server might reply with precheckFlagResponse, which is handled in
          // this.processPrecheckFlagResponse().
        })
        this.flagConsoles.set(id, flagUI)
        return
      }
    })
  }

  processPrecheckFlagResponse(data) {
    this.auxiliaryInputQueue.push({
        type: "flag",
        value: [data.flag, data.result]
    })
  }

  destroyUIObjects() {
    this.terminals.forEach(v => v.destroy())
    this.terminals.clear()

    this.flagConsoles.forEach(v => v.destroy())
    this.flagConsoles.clear()
  }

  processInputs() {
    const inputs = {}

    if (this.auxiliaryInputQueue.length > 0) {
      const input = this.auxiliaryInputQueue.shift()
      inputs[input.type] = input.value
    }

    if ("KeyW" in this.keyStates || "ArrowUp" in this.keyStates) {
      inputs.up = true
    }

    if ("KeyS" in this.keyStates || "ArrowDown" in this.keyStates) {
      inputs.down = true
    }

    if ("KeyA" in this.keyStates || "ArrowLeft" in this.keyStates) {
      inputs.left = true
    }

    if ("KeyD" in this.keyStates || "ArrowRight" in this.keyStates) {
      inputs.right = true
    }

    if ("Escape" in this.keyStates) {
      inputs.escape = true
    }

    return inputs
  }

  iterate() {
    const now = Date.now()
    const ticksToRun = (now - this.lastTickTime) / gameState.MS_PER_TICK | 0
    if (ticksToRun === 0) {
      return
    }

    const inputs = this.processInputs()
    const changes = []

    for (let i = 0; i < ticksToRun; i++) {
      globals.state.tick(inputs)

      changes.push({
        inputs: inputs,
        state: globals.state.export()
      })
    }

    main.wsSend({
      type: "ticks",
      changes: changes
    })

    this.lastTickTime = Date.now()

    globals.visuals.render()
  }
}
