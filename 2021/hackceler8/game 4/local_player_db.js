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

const crypto = require('crypto')
const PlayersDatabaseBase = require("./player_db")
const os = require("os");

class LocalPlayersDatabase extends PlayersDatabaseBase {
  players
  fastTokens

  _savegameDir(username) {
    const dir = os.tmpdir() + "/hackceler8_" + username
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, 0o744);
    }
    return dir
  }

  _ensureInitSavegames(username) {
    if (username in this.savegames) {
      return
    }
    console.log("Savegame dir:", this._savegameDir(username))

    this.savegames[username] = {}
    const dir = this._savegameDir(username)
    const filenames = fs.readdirSync(dir)
    const loaded_savegames = []

    for (const fn of filenames) {
      const game = JSON.parse(fs.readFileSync(dir + "/" + fn))
      if (game.is_backup === true && game.name !== this.preloadedBackupName) {
        continue
      }
      this.savegames[username][game.name] = game
      loaded_savegames.push(game.name)
    }
    console.log("Loaded save games:", loaded_savegames)
  }

  constructor(players) {
    super()

    this.players = players
    Object.freeze(this.players)  // Disable adding new players.

    this.savegames = {}

    this.fastTokens = {}

    this.preloadedBackupName = null

    setInterval(() => {
      this.expireFastTokens()
    }, 1000 * 60 * 15 /* TODO: const 15 min */)
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

  /* savegame data
  name: A user-specified name.
  timestamp: When save was made.
  image: image of where user was.
  state: the save data.
  hash: the version of the game used for creating this.
  */

  _saveSavegameImpl(username, savename, state, is_backup) {
    this._ensureInitSavegames(username)


    const timestamp = Math.floor(+new Date() / 1000)
    const savegameEntry = {"name": savename, "timestamp": timestamp, "state": state, "is_backup": is_backup}

    const dir = this._savegameDir(username)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, 0o744);
    }

    // Nice try :)
    var savename_f = savename.replaceAll(".", "&#46;")
    var savename_f = savename_f.replaceAll("/", "&#47;")

    const filename = dir + "/" + savename_f + ".json"
    fs.writeFileSync(
        filename,
        JSON.stringify(savegameEntry));

    if (is_backup) {
      console.log("Saved backup " + savename)
    } else {
      console.log("Saved savegame " + savename)
    }

    return savegameEntry
  }

  saveSavegame(username, savename, state) {
    const savegameEntry = this._saveSavegameImpl(username, savename, state, false)
    this.savegames[username][savename] = (savegameEntry)
  }

  loadSavegame(username, savename) {
    this._ensureInitSavegames(username)
    for (const sn in this.savegames[username]) {
      const save = this.savegames[username][sn]
      if (save.name == savename) {
        console.log("Loading save", savename)
        return save
      }
    }
    console.error("Failed to find save", savename)
    return undefined
  }

  savegameMeta(username) {
    this._ensureInitSavegames(username)
    // Get all the savegame data, except the state object itself
    if (!(username in this.savegames)) return []

    var savegames = []
    for (const sn in this.savegames[username]) {
      const game = this.savegames[username][sn]
      var duplicate = {}
      Object.keys(game).reduce((result, key) => {
        if(key !== "state") {
           result[key] = game[key];
        }
        return result;
      }, duplicate);
      savegames.push(duplicate)
    }

    return savegames
  }

  // Adds a new save option based on a backup save file.
  setBackup(name) {
    this.preloadedBackupName = name
  }

  saveBackup(username, savename, state) {
    this._saveSavegameImpl(username, savename, state, true)
  }
}

module.exports = LocalPlayersDatabase
