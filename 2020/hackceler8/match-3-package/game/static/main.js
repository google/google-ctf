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

const RES_W = 1024  // Changing this breaks some CSS constants.
const RES_H = 576

let globals = {
  ws: null,  // WebSocket connection.
  visuals: null,  // Video rendering.
  res: null,  // Resource Manager.
  map: null,  // Current loaded map (if any).
  state: null,  // Current game state (if any).
  game: null,  // Game controller and main loop.
  observerState: null,  // Holds observer state, valid only on the client.
  main: null,  // Main object.
  PORTAL_MOCK: false
}

const main = {}
globals.main = main

main.mockEnterShell = async (text) => {
  const eInput = document.getElementById("shell-input-v")
  eInput.value = ""

  let chars = text.split("")

  let promise = new Promise((resolve, reject) => {
    let intervalHandle = setInterval(() => {
      let char = chars.shift()

      if (char) {
        eInput.value += char
      } else {
        clearInterval(intervalHandle)
        resolve()
      }
    }, 200)
  })

  await promise
  eInput.value = ""
}

main.mockSleep = async (ms) => {
  let promise = new Promise((resolve, reject) => {
    setTimeout(() => { resolve() }, ms)
  })
  await promise
}

main.mockPlayTask = async () => {
  const e = document.getElementById("task-box")
  const eShell = document.getElementById("shell")
  e.style.display = "block"
}

main.showError = (text) => {
  const e = document.getElementById("error-box")
  e.innerText = text
  e.style.display = "block"
  e.style.opacity = "1"
}

main.hideError = () => {
  const e = document.getElementById("error-box")
  e.addEventListener("transitionend", () => {
    e.style.display = "none"
    e.innerText = ""
  }, { once: true })
  e.style.opacity = "0"
}

main.showLogin = () => {
  const e = document.getElementById("scene-login")
  e.style.display = "flex"
}

main.hideLogin = () => {
  const e = document.getElementById("scene-login")
  e.style.display = "none"
}

main.handleLogin = () => {
  const sceneEl = document.getElementById("scene-login")
  const username = sceneEl.querySelector("#username").value
  const password = sceneEl.querySelector("#password").value
  const observer = Boolean(
      document.getElementById("use_observer_mode").value === "true"
  )

  const obsEl = document.getElementById("obsname")
  if (obsEl) {
    obsEl.textContent = username
  }

  main.wsSend({
    type: "fullAuth",
    username: username,
    password: password,
    observer: observer
  })
}

main.wsSend = (data) => {
  if (globals.ws.readyState === 1) {
    globals.ws.send(JSON.stringify(data))
  } else {
    main.hideLogin()
    main.showError("Not connected yet, please retry.")
  }
}

main.wsOnOpen = (e) => {
  //main.showError("Connected!")
  setTimeout(() => {
    main.hideError()
  }, 1000)
}

main.wsOnMessage = (e) => {
  let data = null
  try {
    data = JSON.parse(e.data)
  } catch(ex) {
    console.error("Failed to parse packet from server:", e.data)
    return
  }

  if (data.type === "startState") {
    globals.state = gameState.GameState.fromStateDict(data.state, globals.map)
    globals.game.start()
  }

  if (data.type === "plzAuth") {
    // Try fast-auth route.
    const fastToken = localStorage.getItem("fastToken")
    const observer = (
        document.getElementById("use_observer_mode").value === "true"
    )

    if (fastToken) {
      main.wsSend({
        type: "fastAuth",
        token: fastToken,
        observer: observer
      })
      return
    }

    // Fallback to re-login.
    main.showLogin()
  }

  if (data.type === "plzAuthFull") {
    // Fast authentication failed, so we have to fall-back to the normal route.
    // At the same time we can remove the token - it's useless.
    localStorage.removeItem("fastToken")
    main.showLogin()
  }

  if (data.type === "authOK") {
    if (data.hasOwnProperty("fastToken")) {
      localStorage.setItem("fastToken", data.fastToken)
    }
    //main.showError("Logged in!")
    main.hideLogin()
  }

  if (data.type === "authFail") {
    main.showError("Login failed - wrong player id and/or password.")
  }

  if (data.type === "map") {
    let gameMap = new mapUtils.GameMap()
    gameMap.browserLoad(data.map)

    globals.res.loadResources(gameMap.resources)
    .then(() => {
      globals.map = gameMap
      globals.visuals.initialize(globals.map)

      main.wsSend({
        type: "mapReady"
      })
    })
  }

  if (data.type === "terminal") {
    const terminalUI = globals.game.getTerminalUIObject(data.challengeID)

    const decodedData = data.data ? utils.hexToUint8Array(data.data) : null
    if (decodedData) {
      const text = utils.textDecoder.decode(decodedData)
      terminalUI.appendOutput(text)
      terminalUI.setStatus("connect")
    } else {
      terminalUI.setStatus(data.eventType)
    }
  }

  if (data.type === "precheckFlagResponse") {
    globals.game.processPrecheckFlagResponse(data)
  }

  if (data.type === "observeStates") {
    if (data.states) {
      globals.observerState.states = globals.observerState.states.concat(data.states)
      var expectedLastStateId = globals.observerState.states.length - 1
      var actualLastStateId = globals.observerState.states[expectedLastStateId].tick
      if (expectedLastStateId != actualLastStateId) {
        throw "State number " + actualLastStateId + " located in slot " + expectedLastStateId;
      }
    }
    //globals.state = gameState.GameState.fromStateDict(data.state, globals.map)
    //globals.observerState.tick = globals.state.state.tick
  }
}

main.wsOnError = (e) => {
  console.log("wsOnError", e)
  globals.game.stop()
}

main.wsOnClose = (e) => {
  globals.game.stop()
  main.hideLogin()
  main.showError("Disconnected. Attempting to reconnect...")
  setTimeout(() => {
    main.reconnect()
  }, 500)
}

main.reconnect = () => {
  if (globals.ws instanceof WebSocket) {
    globals.ws.close(4001, "Re-making connection for some reason.")
    globals.ws = null
  }

  const loc = document.location
  const protocol = loc.protocol === "http:" ? "ws:" : "wss:"

  let ws = new WebSocket(`${protocol}//${loc.host}/`)
  ws.onopen = main.wsOnOpen
  ws.onmessage = main.wsOnMessage
  ws.onerror = main.wsOnError
  ws.onclose = main.wsOnClose

  globals.ws = ws
}

main.main = () => {
  const observer = Boolean(
      document.getElementById("use_observer_mode").value === "true"
  )
  if (observer) {
    globals.observerState = {}
    globals.observerState.states = []
    globals.observerState.tick = 0
    globals.observerState.mode = "live"
  }

  globals.visuals = new visuals.Visuals()
  globals.res = new resourceManager.ResourceManager()
  globals.game = new game.Game()

  main.reconnect()

  const e = document.getElementById("login-submit")
  e.addEventListener("click", (ev) => {
    main.handleLogin()
    ev.preventDefault()
  })
}

main.onload = () => {
  main.main()
}

window.addEventListener("load", main.onload)
