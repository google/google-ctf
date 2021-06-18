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

// Sets the value of a FlagConsole to the specified flag, so that unsubmitted
// flags persist across reconnects
function setFlag(challengeId, flag) {
  globals.game.auxiliaryInputQueue.push({
    type: "setFlag",
    value: [challengeId, flag]
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

    const intervalHandler = globals.observerState ?
        (() => { this.observerIterate() }) :
        (() => { this.iterate() })

    this.intervalHandle = window.setInterval(
        intervalHandler, Game.LOGIC_CHECK_INTERVAL
    )
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
        flagUI.setValue(entity.value)

        flagUI.setEditHandler(flag => {
          // Called every time the flag is changed, so we can store its value
          setFlag(id, flag)
        })

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

    if ("Space" in this.keyStates) {
        inputs.pickup = true
    }

    return inputs
  }

  iterate() {
    const now = Date.now()
    const ticksToRun = (now - this.lastTickTime) / gameState.MS_PER_TICK | 0
    if (ticksToRun === 0) {
      //globals.visuals.render()
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

  observerProcessInputs() {
    const inputs = {}
    if ("KeyR" in this.keyStates) {
      inputs.restart = true
    } else {
      if ("KeyA" in this.keyStates || "ArrowLeft" in this.keyStates) {
        if ("ShiftLeft" in this.keyStates || "ShiftRight" in this.keyStates) {
          inputs.jumpback = true
        } else {
          inputs.stepback = true
        }
      }
    }

    if ("KeyL" in this.keyStates) {
      inputs.golive = true
    } else {
      if ("KeyD" in this.keyStates || "ArrowRight" in this.keyStates) {
        if ("ShiftLeft" in this.keyStates || "ShiftRight" in this.keyStates) {
          inputs.jumpforward = true
        } else {
          inputs.stepforward = true
        }
      }
    }

    if ("Space" in this.keyStates) {
      if (!this.pauseLatch) {
        inputs.togglePause = true
        this.pauseLatch = true
      }
    } else {
      this.pauseLatch = false
    }

    return inputs
  }

  observerIterate() {
    const now = Date.now()
    const ticksToRun = (now - this.lastTickTime) / gameState.MS_PER_TICK | 0
    if (ticksToRun === 0 && globals.observerState.mode != "live") {
      return
    }
    const inputs = this.observerProcessInputs()

    // State machine for processing inputs

    if (inputs.restart) {
      globals.observerState.tick = 0
      if (globals.observerState.mode == "live") {
        globals.observerState.mode == "play"
      }
    }

    if (inputs.golive) {
      globals.observerState.mode = "live"
    }

    if (inputs.togglePause) {
      if (globals.observerState.mode == "play") {
        globals.observerState.mode = "pause"
      } else if (globals.observerState.mode == "live") {
        globals.observerState.mode = "pause"
      } else {
        globals.observerState.mode = "play"
      }
    }

    if (inputs.stepback) {
      if (globals.observerState.mode == "pause") {
        globals.observerState.tick = globals.observerState.tick - ticksToRun
      } else if (globals.observerState.mode == "play") {
        globals.observerState.tick = globals.observerState.tick - 2 * ticksToRun
      } else {
        // We're live, so switch to play mode to allow rewinds
        globals.observerState.mode = "play"
        globals.observerState.tick = globals.observerState.tick - 2 * ticksToRun
      }
    }

    if (inputs.stepforward) {
      globals.observerState.tick = globals.observerState.tick + ticksToRun
    }

    // Jumpback is just like stepback, but 10x the speed
    if (inputs.jumpback) {
      if (globals.observerState.mode == "pause") {
        globals.observerState.tick = globals.observerState.tick - 10 * ticksToRun
      } else if (globals.observerState.mode == "play") {
        globals.observerState.tick = globals.observerState.tick - 11 * ticksToRun
      } else {
        globals.observerState.mode = "play"
        globals.observerState.tick = globals.observerState.tick - 11 * ticksToRun
      }
    }

    if (inputs.jumpforward) {
      globals.observerState.tick = globals.observerState.tick + 10 * ticksToRun
    }

    // End state machine for processing inputs

    // Live mode: doesn't matter what frame we're on, get the most recent one.
    if (globals.observerState.mode == "live") {
      // Gets dropped down to the most recent frame later
      globals.observerState.tick = Number.MAX_VALUE
    }

    if (globals.observerState.tick < 0) {
      globals.observerState.tick = 0
    }

    if (globals.observerState.mode == "play") {
      globals.observerState.tick = globals.observerState.tick + ticksToRun
    }

    if (globals.observerState.states.length) {
      var liveTick = globals.observerState.states.length - 1
      if (globals.observerState.tick > liveTick) {
        globals.observerState.tick = liveTick
      }

      while (globals.observerState.states[globals.observerState.tick].pruned && globals.observerState.tick < globals.observerState.states.length - 1) {
        globals.observerState.tick = globals.observerState.tick + 1
      }

      globals.state = gameState.GameState.fromStateDict(
          globals.observerState.states[globals.observerState.tick], globals.map)
    }

    main.wsSend({
      type: "observe",
      startTick: globals.observerState.nextTick
    })


    this.lastTickTime = Date.now()

    globals.visuals.render()
  }
}
