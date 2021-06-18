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
const PORT = 4567
const HOST = '0.0.0.0'

const http = require("http")
const websocket = require("ws")
const url = require("url")
const express = require("express")
const path = require("path")
const session = require('express-session')
const fs = require('fs')

const utils = require("./common/utils")
const mapUtils = require("./common/map-utils")

const LocalPlayersDatabase = require("./local_player_db")

const PlayerConnection = require("./player_connection")
const AuthService = require("./auth_service")
const GameService = require("./game_service")

const config = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json")))

const gameMap = new mapUtils.GameMap()
gameMap.nodeLoad(config.map.path, config.map.file)

const playersDB = new LocalPlayersDatabase(config.players)
const gameService = new GameService(gameMap)
const authService = new AuthService(playersDB, gameService)
gameService.setConfig(config)

const app = express()
const formParser = express.urlencoded({extended: false})

app.use(express.static('static'))
app.use('/common', express.static('common'))
app.use('/bundle', express.static(config.map.path))

const defaultAction = (req, res) => {
  res.sendFile(path.join(__dirname, "static", "index.html"))
}

const server = http.createServer(app)
const wss = new websocket.Server({
  noServer: true
})

if (config.fw.filter_by_ip) {
  console.warn(`Setting up IP filtering (ACL: ${config.fw.filter_list})`)

  const allowIP = ip => {
    let filterData = null
    try {
      filterData = fs.readFileSync(path.join(__dirname, config.fw.filter_list))
    } catch(e) {
      console.error("IP ACL file missing")
      return false
    }

    return filterData.toString().split(/\r?\n/).some(
        allowedIP => allowedIP === ip
    )
  }

  server.on("connection", socket => {
    const addr = socket.remoteAddress

    if (!allowIP(addr)) {
      socket.write(
          "HTTP/1.1 402 Payment Required\n" +
          "Content-Type: text/html\n" +
          "\n" +
          "<h1>402 Payment Required</h1>"
      )
      socket.destroy()
      console.warn(`Rejected connection from IP: ${addr}`)
      return null
    }
  })
}

server.on("upgrade", function(request, socket, head) {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request)
  })
})

wss.on('connection', (ws, req) => {
  const playerConn = new PlayerConnection(ws)
  ws.playerConn = playerConn
  ws.on('message', (m) => { ws.playerConn.onMessage(m) })
  ws.on('close', () => { ws.playerConn.onClose() })
  playerConn.attachService(authService)
})

server.listen(PORT, HOST, () => {
  console.log(`Server running at ${HOST}:${PORT}.`)
  console.log(`To play the game connect with a browser to port ${PORT}.`)
  console.log(`Default username and password is: player/asdf`)
  console.log(`Good luck!`)
})

//const repl = require("repl")
//repl.start({})
