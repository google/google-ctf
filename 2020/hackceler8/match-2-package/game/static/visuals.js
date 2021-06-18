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

const visuals = {}
// Set to true to enable FPS counter (written to console log every second)
visuals.fps_enable = false

visuals.fps_last_measurement_time = (new Date()).getTime()
visuals.fps_frame_count = 0
visuals.fps_prev_frame_time = (new Date()).getTime()
visuals.fps_max_gap = 0

visuals.Visuals = class Visuals {
  // Private.
  map
  elGame  // Parent for all the main layers.
  elMainParallax  // Parent element for all parallax layers.
  elMainFront  // Parent element for all foreground/player/background layers.
  elMainOverlay  // Parent element for all overlay layers.
  elMainHud  // Parent element for all HUD elements.

  elParallax = []
  elFore = []
  elEntities = null
  elBack = []
  elOverlay = []

  elAreaName = null
  elRespawnPanel = null
  elRespawnCounter = null
  elEndPanel = null
  elTimer = null
  elFlags = []

  wPercent
  hPercent

  viewportX
  viewportY

  playerCanvasClearRects = []

  gameAreas = []
  currentArea = null
  previousAreaName = null

  playerIsDead = false
  showingVictory = false

  lastSolvedCount = 0
  lastTimer = null

  constructor() {
    this.elGame = document.getElementById("game")
    this.elMainParallax = document.getElementById("parallax")
    this.elMainFront = document.getElementById("front")
    this.elMainOverlay = document.getElementById("overlay")

    // HUD.
    this.elMainHud = document.getElementById("hud")
    this.elAreaName = document.getElementById("area-name")
    this.elRespawnPanel = document.getElementById("respawn-panel")
    this.elRespawnCounter = document.getElementById("respawn-panel-counter")
    this.elEndPanel = document.getElementById("end-panel")
    this.elTimer = document.getElementById("timer")

    for (let i = 0; i < 8; i++) {
      const el = document.getElementById(`flag-${i}`)
      el.style.display = "none"
      this.elFlags.push(el)
    }
  }

  reset() {
    this.map = null

    this.elParallax = []
    this.elFore = []
    this.elEntities = null
    this.elBack = []
    this.elOverlay = []

    this.elFront = []  // elFore + elEntities + elBack

    this.gameAreas = []
    this.currentArea = null
    this.previousAreaName = ""

    this.playerIsDead = false
    this.showingVictory = false

    this.lastSolvedCount = 0
    for (let i = 0; i < 8; i++) {
      this.elFlags[i].style.display = "none"
    }

    this.lastTimer = null
    this.elTimer.textContent = "??:??"

    const containers = [
      this.elMainParallax, this.elMainFront, this.elMainOverlay
    ]
    containers.forEach(e => {
      while (e.lastChild) {
        e.removeChild(e.lastChild)
      }
    })
  }

  initialize(map) {
    this.reset()
    this.map = map

    this.initializeParallax()
    this.initializeCanvases()
    this.initializeOverlays()
    this.initializeGameAreas()
  }

  render() {
    let time = (new Date()).getTime()
    if (visuals.fps_enable) {
      let tick = globals.state.state.tick
        visuals.fps_frame_count = visuals.fps_frame_count + 1
      if (time - visuals.fps_prev_frame_time > visuals.fps_max_gap) {
        visuals.fps_max_gap = time - visuals.fps_prev_frame_time
      }
      if (time - visuals.fps_last_measurement_time > 1000) {
        console.log("FPS: " + (visuals.fps_frame_count) + " Max Gap: " + (visuals.fps_max_gap / 1000) + "s")
        visuals.fps_frame_count = 0
        visuals.fps_last_measurement_time = time
        visuals.fps_max_gap = 0
      }
      visuals.fps_prev_frame_time = time
    }

    if (globals.state === null) {
      return
    }
    const s = globals.state.state

    this.clearPlayerCanvasFast()
    this.setCameraCenterAt(s.entities.player.x, s.entities.player.y)

    const playerEntity = s.entities.player

    this.updateAreaIfNeeded(playerEntity.x, playerEntity.y)

    // TODO: When state will implement the quad tree or whatnot, use it to just
    // grab entities that are within the viewport.
    Object.entries(s.entities).forEach(e => {
      const entity = e[1]
      if (entity === playerEntity) {
        return  // Player is rendered last.
      }

      this.renderEntity(entity)
    })

    this.renderEntity(s.entities.player)

    if (playerEntity.dead) {
      if (!this.playerIsDead) {
        this.elGame.style.filter = "grayscale(100%)"
        this.playerIsDead = true
        this.showRespawnPanel()
      }

      this.updateRespawnCounter()
    } else {
      if (this.playerIsDead) {
        this.hideRespawnPanel()
        this.elGame.style.filter = ""
        this.playerIsDead = false
      }
    }

    if (s.victory) {
      if (!this.showingVictory) {
        this.elGame.style.filter = "grayscale(100%)"
        this.showingVictory = true
        this.showEndPanel()
      }
    } else {
      if (this.showingVictory) {
        this.hideEndPanel()
        this.elGame.style.filter = ""
      }
    }

    let solvedCount = 0
    for (let k in s.challenges) {
      solvedCount += s.challenges[k].solved
    }

    if (this.lastSolvedCount != solvedCount) {
      this.lastSolvedCount = solvedCount

      for (let i = 0; i < 8; i++) {
        this.elFlags[i].style.display = (i < solvedCount) ? "block" : "none"
      }
    }

    const timeSeconds = (time / 1000)|0
    if (timeSeconds != this.lastTimer) {
      this.lastTimer = timeSeconds

      const t = timeSeconds - s.startTime
      let text = "???"
      if (t > 90 * 60) {
        text = "90:00"
      } else if (t >= 0) {
        const minutes = (t / 60) | 0
        const seconds = (t % 60)
        text = String(minutes).padStart(2, "0") + ":" +
               String(seconds).padStart(2, "0")
      }

      this.elTimer.textContent = text
    }
  }

  showEndPanel() {
    this.elEndPanel.style.display = "block"
  }

  hideEndPanel() {
    this.elEndPanel.style.display = "none"
  }

  showRespawnPanel() {
    this.elRespawnPanel.style.display = "block"
  }

  hideRespawnPanel() {
    this.elRespawnPanel.style.display = "none"
  }

  updateRespawnCounter() {
    const s = globals.state.state
    let ticksRemaining = s.entities.player.respawnTick - s.tick
    if (!ticksRemaining) {
      ticksRemaining = 0
    }

    const secondsLeft = ticksRemaining / gameState.TICKS_PER_SECOND
    this.elRespawnCounter.textContent = secondsLeft.toFixed(1)
  }

  playAreaName(text) {
    const LETTER_DELAY = 50  // Milliseconds.
    const HIDE_DELAY = 5000 // Milliseconds.

    window.clearTimeout(this.playAreaNameTimeoutHandle)

    this.elAreaName.textContent = ""

    this.elAreaName.style.transition = "opacity 0s"
    this.elAreaName.style.opacity = 1

    let letters = text.trim().split("")

    const fadeOut = () => {
      this.elAreaName.style.transition = "opacity 1s"
      this.elAreaName.style.opacity = 0
      this.playAreaNameTimeoutHandle = null
    }

    const playNext = () => {
      if (letters.length === 0) {
        // End of text?
        this.playAreaNameTimeoutHandle = window.setTimeout(fadeOut, HIDE_DELAY)
        return
      }

      let textToAdd = ""
      while (true) {
        const letter = letters.shift()
        textToAdd += letter

        if (letter === " ") {
          continue
        }

        break
      }

      this.elAreaName.textContent += textToAdd
      this.playAreaNameTimeoutHandle = window.setTimeout(playNext, LETTER_DELAY)
    }

    this.playAreaNameTimeoutHandle = window.setTimeout(playNext, 0)
  }

  clearPlayerCanvasFast() {
    this.playerCanvasClearRects.forEach(posAndSize => {
      this.elContext.clearRect(...posAndSize)
    })

    this.playerCanvasClearRects = []
  }

  renderEntity(e) {
    if (!e.visible) {
      return false
    }

    if (e.x > this.viewportX + RES_W ||
        e.y > this.viewportY + RES_H) {
      return false
    }

    if (e.x < this.viewportX - 64 ||
        e.y < this.viewportY - 64) {
      return false
    }

    const frameset = e.frameSet
    const tile = frameset ?
        globals.map.framesets[frameset].getFrame(e.frameState, e.frame).tile :
        globals.map.globalTiles[e.tileGID]

    if (!tile) {
      console.warn("Entity missing frameSet or tileGID:", e)
      return false
    }

    if (e.x + tile.tileW < this.viewportX ||
        e.y + tile.tileH < this.viewportY) {
      return false
    }

    const tileset = tile.tileset

    // TODO: this is used also in drawTiles - perhaps move it to a function?
    // or rather actually attach all images to all tilesets before we start
    // the rendering business.
    let img = tileset.image
    if (!img) {
      img = tileset.image = globals.res.r[tileset.imageSrc].img
    }

    const ctx = this.elContext

    const xOffset = (globals.state.state.entities.player.x - (RES_W/2))
    const yOffset = (globals.state.state.entities.player.y - (RES_H/2))

    if (e.flipImage) {
      ctx.save()
      ctx.scale(-1, 1)
      ctx.drawImage(
          img,
          tile.x, tile.y, tile.tileW, tile.tileH,
          (-e.x - tile.tileW + xOffset), (e.y - yOffset), tile.tileW, tile.tileH
      )
      ctx.restore()
    } else {
      ctx.drawImage(
          img,
          tile.x, tile.y, tile.tileW, tile.tileH,
          (e.x - xOffset), (e.y - yOffset), tile.tileW, tile.tileH
      )
    }

    this.playerCanvasClearRects.push([(e.x - xOffset), (e.y - yOffset), tile.tileW, tile.tileH])
    return true
  }

  // Private.
  updateAreaIfNeeded(playerX, playerY) {
    if (this.currentArea &&
        this.isPointInBoundingBox(playerX, playerY, this.currentArea.bb)) {
      // Player is still in the same area.
      return false
    }

    // Player potentially changed the area (or is still outside of any defined
    // area).
    let newArea = null

    const areaCount = this.gameAreas.length
    for (let i = 0; i < areaCount; i++) {
      const area = this.gameAreas[i]
      if (this.isPointInBoundingBox(playerX, playerY, area.bb)) {
        newArea = area
        break
      }
    }

    if (this.currentArea === null && newArea === null) {
      // Player is still outside of any area.
      return false
    }

    if (newArea === null) {
      // Player left defined areas.
      this.currentArea = null

      // Leave the previous filter on.
      // Also, on purpose don't reset this.previousAreaName.
      //this.elMainParallax.style.filter = ""
      //this.elMainOverlay.style.filter = ""
      return true
    }

    // Player is in an actual area.
    this.currentArea = newArea
    this.elMainParallax.style.filter = newArea.parallaxFilter
    //this.elMainOverlay.style.filter = newArea.overlayFilter

    if (this.previousAreaName != this.currentArea.name) {
      this.playAreaName(`Location: ${newArea.name}`)
    }

    this.previousAreaName = this.currentArea.name

    return true
  }

  isPointInBoundingBox(x, y, bb) {
    return x >= bb[0] && x < bb[2] && y >= bb[1] && y < bb[3]
  }

  fixStyleString(s) {
    // Changes " red; " to "red".
    s = s.trim()
    return s.endsWith(';') ? s.slice(0, -1) : s
  }

  initializeGameAreas() {
    const areas = this.map.layers.metadata.objectsByType.area
    if (!areas) {
      return
    }

    areas.forEach(area => {
      this.gameAreas.push({
        bb: [ area.x, area.y, area.x + area.width, area.y + area.height ],
        name: area.name,
        overlayFilter: this.fixStyleString(area.properties.overlay_filter),
        parallaxFilter: this.fixStyleString(area.properties.parallax_filter)
      })
    })
  }

  initializeLayerType(prefix, callback) {
    let i = 0
    while (true) {
      const name = `${prefix}${i}`
      const layer = this.map.layers[name]
      if (!layer) {
        break
      }

      callback(name, i, layer)

      i++
    }
  }

  createCanvas(w, h, zIndex) {
    const el = document.createElement("CANVAS")
    el.width = w
    el.height = h
    el.style.zIndex = `${zIndex}`
    el.style.width = `${100 * w / RES_W}%`
    el.style.height = `${100 * h / RES_H}%`
    //el.style.top= `0%`
    //el.style.left = `0%`
    return el
  }

  drawTiles(c, layer) {
    const ctx = c.getContext("2d")
    const tileW = this.map.tileW
    const tileH = this.map.tileH


    var player = undefined
    if (globals.state) {
      player = globals.state.state.entities.player
    }

    ctx.clearRect(0, 0, c.width, c.height)
    layer.tiles.forEach((tile, index) => {
      const x = (index % this.map.columns) * tileW
      const y = ((index / this.map.columns)|0) * tileH

      if (player) {
        if (Math.abs(x - player.x > 19 * 32)) { return; }
        if (Math.abs(x - player.y > 9 * 32)) { return; }
      }

      let img = tile.tileset.image
      if (!img) {
        img = globals.res.r[tile.tileset.imageSrc].img
        tile.tileset.image = img
      }

      ctx.drawImage(img, tile.x, tile.y, tileW, tileH, x, y, tileW, tileH)
    })
  }

  initializeParallax() {
    this.initializeLayerType("parallax", (name, idx, layer) => {
      const img = globals.res.r[layer.imageSrc].img
      const c = this.createCanvas(img.width * 2, img.height, idx)
      const ctx = c.getContext('2d')

      c.dataset.xMoveRatio = layer.parallaxXMoveRatio
      c.dataset.yMoveRatio = layer.parallaxYMoveRatio

      ctx.drawImage(img, 0, 0)
      ctx.drawImage(img, img.width, 0)
      this.elParallax.push(c)
    })

    this.elMainParallax.append(...this.elParallax)
  }

  initializeOverlays() {
    this.initializeLayerType("overlay", (name, idx, layer) => {
      const img = globals.res.r[layer.imageSrc].img
      const c = this.createCanvas(img.width, img.height, 500 + idx)
      const ctx = c.getContext('2d')

      ctx.drawImage(img, 0, 0)
      ctx.drawImage(img, img.width, 0)
      this.elOverlay.push(c)
    })

    this.elMainOverlay.append(...this.elOverlay)
  }

  initializeCanvases() {
    this.initializeLayerType("bg", (name, idx, layer) => {
      const c = this.createCanvas(this.map.canvasW, this.map.canvasH, idx + 100)
      this.drawTiles(c, layer)
      this.elBack.push(c)
    })

    this.elEntities = this.createCanvas(RES_W, RES_H, 200)
    this.elContext = this.elEntities.getContext("2d")

    this.initializeLayerType("fg", (name, idx, layer) => {
      const c = this.createCanvas(this.map.canvasW, this.map.canvasH, idx + 300)
      this.drawTiles(c, layer)
      this.elFore.push(c)
    })

    this.elFront = this.elBack.concat(this.elEntities, this.elFore)
    this.elMainFront.append(...this.elFront)

    this.wPercent = 100 * this.map.canvasW / RES_W
    this.hPercent = 100 * this.map.canvasH / RES_H
  }

  // TODO: Move this to some utils
  clamp(v, min, max) {
    return Math.min(Math.max(v, min), max)
  }

  setCameraCenterAt(xPixels, yPixels) {
    let xPercent = 100 * xPixels / RES_W - 50.0   // These are floating points.
    let yPercent = 100 * yPixels / RES_H - 50.0

    // Note: This will do funny things if the map is smaller than the screen
    // size.
    //xPercent = this.clamp(xPercent, 50.0, this.wPercent - 50.0) - 50.0
    //yPercent = this.clamp(yPercent, 50.0, this.hPercent - 50.0) - 50.0

    this.viewportX = (xPercent * RES_W / 100) | 0
    this.viewportY = (yPercent * RES_H / 100) | 0

    this.elFront.forEach(el => {
      el.style.left =  (-xPercent) + "%"
      el.style.top = (-yPercent) + "%"
    })

    this.elEntities.style.left = "0"
    this.elEntities.style.top = "0"

    const diffBottom = this.hPercent - 100.0 - yPercent

    // Parallax.
    this.elParallax.forEach(el => {
      const xMoveRatio = el.dataset.xMoveRatio
      const yMoveRatio = el.dataset.yMoveRatio

      // Vertical.
      el.style.bottom = `-${diffBottom * yMoveRatio}%`
      el.style.left = `-${xPercent * xMoveRatio}%`
    })
  }
}
