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

const flagConsole = {}

flagConsole.FlagConsole = class FlagConsole {
  // Public fields.
  flagConsoleID = null

  // Private fields.
  el = null  // Main terminal DOM element.
  outputEl = null
  inputEl = null
  parentEl = null
  inputCb = null

  isVisible = false
  outputSize = 0

  // Public methods.
  constructor(flagConsoleID) {
    this.flagConsoleID = flagConsoleID
    this.buildDOMElement()
    this.attachDOMElement()
  }

  destroy() {
    this.el.remove()
  }

  show() {
    if (this.isVisible) {
      return
    }

    this.el.style.display = "block"
    this.isVisible = true

    this.inputEl.focus()
  }

  hide() {
    if (!this.isVisible) {
      return
    }

    this.el.style.display = "none"
    this.isVisible = false
  }

  setInputHandler(cb) {
    this.inputCb = cb
  }

  setStatus(status) {
    let text = {
      "start": "Enter password (flag):",
      "good": "Access Granted!",
      "fail": "Access Denied. Enter correct password (flag):",
      "solved": "Already solved!"
    }[status] || "???"

    this.outputEl.textContent = text
  }

  // Private methods.
  submitInput() {
    const v = this.inputEl.value
    this.inputEl.value = ""

    if (this.inputCb) {
      this.inputCb(v)
    }
  }

  buildDOMElement() {
    const template = document.getElementById("flag-console")
    const fragment = template.content.cloneNode(true)
    this.el = fragment.querySelector(".flag-console-box")
    this.inputEl = fragment.querySelector(".flag-console-input")
    this.outputEl = fragment.querySelector(".flag-console-output")

    //this.setStatus("disconnect")

    this.inputEl.dataset.flagConsoleID = this.flagConsoleID
    this.inputEl.addEventListener("keydown", e => {
      if (e.code === "Enter" || e.code === "NumpadEnter") {
        this.submitInput()
      }

      if (e.code === "Escape") {
        // Escape should actually be propagated so it can be handled by the
        // game logic.
        return
      }

      e.stopPropagation()
    })
  }

  attachDOMElement() {
    this.parentEl = document.getElementById("game")
    this.parentEl.appendChild(this.el)
  }
}
