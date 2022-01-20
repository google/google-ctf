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

const fs = require('fs')
const net = require("net")

class ChallengeConnector {
  // The amount of data that should be kept from previous connections.
  static LAST_DATA_SIZE = 4 * 1024

  // The actual maximum amount of data that can be kept.
  static LAST_BUFFER_SIZE = 2 * ChallengeConnector.LAST_DATA_SIZE

  connected = false

  // Private.
  s = null  // Socket.
  callbacks = null
  disconnectSent = true  // Whether disconnect event was already sent.
  reconnectInProgress = false
  waitingData = []
  lastBuffer = null
  lastBufferDataSize = 0
  textContent = null
  fileContent = null

  constructor(text, file, callbacks) {
    this.callbacks = callbacks

    if (text) {
      this.textContent = Buffer.from(text, "utf-8")
    }

    if (file) {
      this.fileContent = fs.readFileSync(file)
    }

    this.lastBuffer = Buffer.alloc(ChallengeConnector.LAST_BUFFER_SIZE)

    this.onData = this.onDataWorker.bind(this)
  }

  // Note: Write will trigger a reconnect if needed (though reconnect can be
  // called explicitly as well). This means that calling write with an empty
  // string/buffer will just make sure that the terminal is connected.
  write(data) {
    if (!Buffer.isBuffer(data)) {
      if (typeof data === "string") {
        data = Buffer.from(data)
      } else {
        throw "Invalid argument type for challenge connector's write()."
      }
    }

    this.appendLastData(data)
    if (!this.connected) {
      if (data.length > 0) {
        this.waitingData.push(data)
      }
      this.reconnect()
    } else {
      if (data.length > 0) {
        this.s.write(data)
      }
    }
  }

  onClose() {}
  onError() {}
  onEnd() {}

  emitStaticContent() {
    console.log("emitStaticContent")
    if (!this.onData) {
      return
    }

    if (this.textContent) {
      this.onData(this.textContent)
    }

    if (this.fileContent) {
      this.onData(this.fileContent)
    }
  }

  reconnect() {
    console.log("reconnect")
    if (this.reconnectInProgress) {
      return
    }

    this.emitStaticContent()
  }

  // Private.
  appendLastData(data) {
    console.log("appendLastData")
    // If there is enough data to fulfill the requirements, just ignore the
    // content of the buffer and overwrite it with last LAST_DATA_SIZE bytes.
    if (data.length >= ChallengeConnector.LAST_DATA_SIZE) {
      const startIdx = data.length - ChallengeConnector.LAST_DATA_SIZE
      const endIdx = data.length
      data.copy(this.lastBuffer, 0, startIdx, endIdx)
      this.lastBufferDataSize = ChallengeConnector.LAST_DATA_SIZE
      return
    }

    // If there is less data, see if it fits inside the buffer without the need
    // to shift it.
    if (data.length <= this.lastBuffer.length - this.lastBufferDataSize) {
      data.copy(this.lastBuffer, this.lastBufferDataSize)
      this.lastBufferDataSize += data.length
      return
    }

    // Otherwise calculate the required shift and move it (minimize the amounts
    // of shifts needed).
    const startIdx =  this.lastBufferDataSize + data.length -
                      ChallengeConnector.LAST_DATA_SIZE
    const endIdx = this.lastBufferDataSize
    this.lastBuffer.copy(this.lastBuffer, 0, startIdx, endIdx)

    const shiftedLength = endIdx - startIdx
    data.copy(this.lastBuffer, shiftedLength)
    this.lastBufferDataSize = shiftedLength + data.length
  }

  emitDisconnect() {
    console.log("emitDisconnect")
    if (!this.disconnectSent) {
      // Notify about disconnecting.
      this.disconnectSent = true
      this.callbacks.disconnect()
    }
  }

  onDataWorker(data) {
    console.log("onDataWorker")
    this.callbacks.data(data)
    this.appendLastData(data)
  }
}

module.exports = ChallengeConnector
