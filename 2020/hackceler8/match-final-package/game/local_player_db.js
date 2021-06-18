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

const crypto = require('crypto')
const PlayersDatabaseBase = require("./player_db")

// TODO: add a time out that will periodically clean expired fastToken (e.g.
// every 120 minutes).
class LocalPlayersDatabase extends PlayersDatabaseBase {
  players
  fastTokens

  constructor(players) {
    super()

    this.players = players
    Object.freeze(this.players)  // Disable adding new players.

    this.fastTokens = {}

    setInterval(() => {
      this.expireFastTokens()
    }, 1000 * 60 * 120 /* TODO: const 120 min */)
  }

  expireFastTokens() {
    const now = utils.unixTimestamp()
    const tokensToDelete = []

    for (const token in this.fastTokens) {
      const playerInfo = this.fastTokens[token]

      if (playerInfo._fastToken !== token ||
          now >= playerInfo._fastTokenExpiry) {
        tokensToDelete.push(token)
        delete playerInfo._fastToken
        delete playerInfo._fastTokenExpiry
      }
    }

    tokensToDelete.forEach(token => {
      delete this.fastTokens[token]
    })
  }

  getPlayerInfo(username) {
    if (!this.players.hasOwnProperty(username)) {
      return null
    }

    const playerInfo = this.players[username]
    playerInfo.username = username

    return playerInfo
  }

  login(username, password) {
    if (typeof username !== "string") {
      return false
    }

    if (typeof password !== "string") {
      return false
    }

    const playerInfo = this.getPlayerInfo(username)
    if (!playerInfo) {
      return false
    }

    // TODO: Perhaps do some more fancy PBKDFing.
    const providedHash = (() => {
      const hash = crypto.createHash("sha256")
      hash.update(password)
      return Buffer.from(hash.digest("hex"))
    })(password)
    const knownHash = Buffer.from(playerInfo.hash)

    if (!crypto.timingSafeEqual(providedHash, knownHash)) {
      return false
    }

    this.refreshFastToken(playerInfo)
    return playerInfo
  }

  loginFast(fastToken) {
    if (typeof fastToken !== "string") {
      return false
    }

    if (fastToken.length !== 64) {
      return false
    }

    if (!this.fastTokens.hasOwnProperty(fastToken)) {
      return false
    }

    const playerInfo = this.fastTokens[fastToken]

    const now = utils.unixTimestamp()
    if (now >= playerInfo._fastTokenExpiry) {
      // Expired.
      delete this.fastTokens[playerInfo._fastToken]
      delete playerInfo._fastToken
      delete playerInfo._fastTokenExpiry
      return false
    }

    this.refreshFastToken(playerInfo)
    return playerInfo
  }

  refreshFastToken(playerInfo) {
    const now = utils.unixTimestamp()

    // Refresh current token (if any).
    if (playerInfo._fastToken) {
      delete this.fastTokens[playerInfo._fastToken]
      delete playerInfo._fastToken
      delete playerInfo._fastTokenExpiry
    }

    // Create a new token.
    const fastToken = crypto.randomBytes(32).toString("hex")
    playerInfo._fastToken = fastToken
    playerInfo._fastTokenExpiry = now + (3600 * 2)  // TODO: const 2h

    this.fastTokens[fastToken] = playerInfo
  }
}

module.exports = LocalPlayersDatabase
