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

const terminal = {}

terminal.Terminal = class Terminal {
  // Public fields.
  static MAX_SIZE = 8 * 1024  // Characters.
  static CLEANUP_TRIGGER = 10 * 1024 // Remove characters when exceeded.

  terminalID = null

  // Private fields.
  el = null  // Main terminal DOM element.
  outputEl = null
  inputEl = null
  parentEl = null
  inputCb = null
  promptEl = null

  isVisible = false
  outputSize = 0

  // Public methods.
  constructor(terminalID) {
    this.terminalID = terminalID
    this.buildDOMElement()
    this.attachDOMElement()
    //this.show() // REMOVE ME
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

  appendOutput(data) {
    this.outputEl.appendChild(
      document.createTextNode(data)
    )
    this.outputSize += data.length

    if (this.outputSize > Terminal.CLEANUP_TRIGGER) {
      const before = this.outputSize
      this.outputEl.textContent = this.outputEl.textContent.slice(
          -Terminal.MAX_SIZE
      )
      this.outputSize = this.outputEl.textContent.length
    }

    this.outputEl.scrollTop = this.outputEl.scrollHeight
  }

  resetOutput(data) {
    this.outputEl.textContent = ""
    this.outputSize = 0
  }

  setInputHandler(cb) {
    this.inputCb = cb
  }

  setStatus(status) {
    let color = "pink"

    switch (status) {
      case "connecting": color = "yellow"; break
      case "connect": color = "#0f0"; break
      case "error": color = "red"; break
      case "disconnect": color = "black"; break
    }

    this.promptEl.style.backgroundColor = color
  }

  // Private methods.
  submitInput() {
    const v = this.inputEl.value
    this.inputEl.value = ""

    if (this.inputCb) {
      this.inputCb(v + "\n")
    }
  }

  buildDOMElement() {
    const template = document.getElementById("terminal")
    const fragment = template.content.cloneNode(true)
    this.el = fragment.querySelector(".terminal-box")
    this.inputEl = fragment.querySelector(".terminal-input-v")
    this.outputEl = fragment.querySelector(".terminal-output")
    this.promptEl = fragment.querySelector(".terminal-prompt")

    this.setStatus("disconnect")

    this.inputEl.dataset.terminalID = this.terminalID
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
