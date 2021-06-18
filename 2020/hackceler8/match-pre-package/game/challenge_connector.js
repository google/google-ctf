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

const net = require("net")

class ChallengeConnector {
  // The amount of data that should be kept from previous connections.
  static LAST_DATA_SIZE = 4 * 1024

  // The actual maximum amount of data that can be kept.
  static LAST_BUFFER_SIZE = 2 * ChallengeConnector.LAST_DATA_SIZE

  connected = false

  // Private.
  s = null  // Socket.
  host = null
  port = null
  callbacks = null
  disconnectSent = true  // Whether disconnect event was already sent.
  reconnectInProgress = false
  waitingData = []
  lastBuffer = null
  lastBufferDataSize = 0

  constructor(host, port, callbacks) {
    this.host = host
    this.port = port
    this.callbacks = callbacks

    this.lastBuffer = Buffer.alloc(ChallengeConnector.LAST_BUFFER_SIZE)

    this.onConnect = this.onConnectWorker.bind(this)
    this.onClose = this.onCloseWorker.bind(this)
    this.onData = this.onDataWorker.bind(this)
    this.onEnd = this.onEndWorker.bind(this)
    this.onError = this.onErrorWorker.bind(this)
  }

  // This DOES NOT consume the returned data.
  getLastData() {
    const startIdx = Math.max(
        0,
        this.lastBufferDataSize - ChallengeConnector.LAST_DATA_SIZE
    )
    const endIdx = Math.min(
        this.lastBufferDataSize,
        startIdx + ChallengeConnector.LAST_DATA_SIZE
    )

    const returnBuffer = Buffer.alloc(endIdx - startIdx)
    this.lastBuffer.copy(returnBuffer, 0, startIdx, endIdx)
    return returnBuffer
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

  closeConnection() {
    if (this.reconnectInProgress) {
      // An error has happened when reconnecting.
      if (this.connected) {
        console.error("ChallengeConnector assumption error (1)")
      }

      this.waitingData = []  // Purge any data that would be written.

      this.reconnectInProgress = false
      this.callbacks.error()  // Reconnect error.
      return
    }

    if (!this.connected) {
      return
    }
    this.connected = false
    this.emitDisconnect()

    // Remove listeners so they don't fire needlessly / redundantly.
    this.s
      .removeListener("close", this.onClose)
      .removeListener("error", this.onError)
      .removeListener("end", this.onEnd)

    this.s.destroy()
    this.s = null
  }

  reconnect() {
    if (this.reconnectInProgress) {
      return
    }

    this.closeConnection()

    this.s = new net.Socket()
    this.disconnectSent = false

    this.s
      .on("close", this.onClose)
      .on("data", this.onData)
      .on("end", this.onEnd)
      .on("error", this.onError)
      .on("connect", this.onConnect)

    this.callbacks.connecting()
    this.reconnectInProgress = true
    this.s.connect(this.port, this.host)
  }

  // Private.
  appendLastData(data) {
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
    if (!this.disconnectSent) {
      // Notify about disconnecting.
      this.disconnectSent = true
      this.callbacks.disconnect()
    }
  }

  onConnectWorker() {
    this.reconnectInProgress = false
    this.connected = true

    // Flush waiting data buffer.
    this.waitingData.forEach(data => this.s.write(data))
    this.waitingData = []

    this.callbacks.connect()
  }

  onCloseWorker(hadError) {
    this.closeConnection()
  }

  onDataWorker(data) {
    this.callbacks.data(data)
    this.appendLastData(data)
  }

  onEndWorker() {
    this.closeConnection()
  }

  onErrorWorker(error) {
    this.closeConnection()
  }
}

// Example code:
// let k = new ChallengeConnector("192.168.2.198", 7000, {
//   connecting: () => { console.log("CONNECTING....") },
//   connect: () => { console.log("CONNECTED") },
//   data: data => { console.log("DATA", data) },
//   disconnect: () => { console.log("DISCONNECT") },
//   error: () => { console.log("ERROR") }
// })
// k.write("1\n")
//
// setTimeout(() => { k.write("3\n") }, 2000)
// setTimeout(() => { k.write("1\n") }, 4000)
// setTimeout(() => { k.closeConnection() }, 6000)
//
// var done = (function wait () { if (!done) setTimeout(wait, 1000) })();

module.exports = ChallengeConnector

