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

const mapUtils = {}

mapUtils.IMAGE_LAYER = "imagelayer"
mapUtils.TILE_LAYER = "tilelayer"
mapUtils.OBJECT_LAYER = "objectgroup"

mapUtils.MapFrameset = class MapFrameset {
  // Public fields.
  states = {}  // Dictionary of dictionaries of tiles.
  defaultFrame = null  // Default frame in case something goes wrong.

  // Private fields.
  mapObj = null
  tileset = null

  // Public.
  constructor(tileset, mapObj) {
    this.tileset = tileset
    this.mapObj = mapObj

    this.processTileset()

    this.tileset.frameset = this
  }

  getFrames(state) {
     if (!this.states.hasOwnProperty(state)) {
      return [this.defaultFrame]
    }

    return this.states[state]
  }

  getFrame(state, frameIndex) {
    if (!this.states.hasOwnProperty(state)) {
      return this.defaultFrame
    }

    const stateFrames = this.states[state]
    if (frameIndex >= stateFrames.length) {
      return this.defaultFrame
    }

    return stateFrames[frameIndex]
  }

  // Private.
  processTileset() {
    // If a tile has a custom property named "frame_state", add it (and perhaps
    // multiple other tiles that make an animation) to the frame set.
    this.tileset.tiles.forEach(tile => {
      if (!tile.properties.hasOwnProperty("frame_state")) {
        return
      }

      const frames = []
      if (tile.animation) {
        // Copy frames from animation.
        tile.animation.forEach(frame => {
          frames.push({
            tile: this.tileset.tiles[frame.tileid],
            duration: frame.duration  // Milliseconds.
          })
        })
      } else {
        // It's only a single frame.
        frames.push({
          tile: tile,
          duration: 1000  // Milliseconds. Default to 1 second.
        })
      }

      this.states[tile.properties.frame_state] = frames

      if (tile.properties.default) {
        // Set the fallback frame.
        this.defaultFrame = {
          tile: tile,
          duration: 1000  // Milliseconds. Default to 1 second.
        }
      }
    })
  }
}

mapUtils.MapTileset = class MapTileset {
  // Public fields.
  firstGID = null
  imageW = null
  imageH = null
  tileW = null
  tileH = null
  name = null
  tiles = []
  image = null  // Image object (might be null if image is not loaded).
  imageSrc = null  // Image file name.
  columns = null
  rows = null
  count = null
  properties = {}  // Custom properties.


  // Private fields.
  mapObj = null

  // Public.
  constructor(rawData, mapObj) {
    this.mapObj = mapObj

    this.firstGID = rawData.firstgid
    this.imageW = rawData.imagewidth
    this.imageH = rawData.imageheight
    this.tileW = rawData.tilewidth
    this.tileH = rawData.tileheight
    this.name = rawData.name
    this.imageSrc = rawData.image

    this.columns = this.imageW / this.tileW | 0
    this.rows = this.imageH / this.tileH | 0
    this.count = this.columns * this.rows

    console.assert(this.count === rawData.tilecount,
        `Tile count mismatch! ${this.count} vs expected ${rawData.tilecount}`)

    if (rawData.hasOwnProperty("properties")) {
      rawData.properties.forEach(property => {
        this.properties[property.name] = property.value
      })
    }

    this.processTiles(rawData.tiles || [])
  }

  processTiles(tiles) {
    const tilePropertyCache = {}
    tiles.forEach(e => {
      tilePropertyCache[e.id] = e
    })

    for (let i = 0; i < this.count; i++) {
      const x = i % this.columns
      const y = i / this.columns | 0

      const properties = {}
      let collisions = []
      let animation = null

      if (tilePropertyCache.hasOwnProperty(i)) {
        const tile = tilePropertyCache[i]

        if (tile.hasOwnProperty("objectgroup")) {
          if (tile.objectgroup.hasOwnProperty("objects")) {
            collisions = tile.objectgroup.objects
          }
        }

        if (tile.hasOwnProperty("properties")) {
          tile.properties.forEach(property => {
            properties[property.name] = property.value
          })
        }

        if (tile.hasOwnProperty("animation")) {
          animation = tile.animation
        }
      }

      this.tiles[i] = {
        collisions: collisions,
        x: x * this.tileW,
        y: y * this.tileH,
        tileW: this.tileW,
        tileH: this.tileH,
        tileset: this,
        GID: this.firstGID + i,
        properties: properties,
        animation: animation
      }
    }
  }
}

// TODO: Split into 3 separate sub-classes?
mapUtils.MapLayer = class MapLayer {
  // Public fields.
  name = null
  type = null               // One of: IMAGE_LAYER, TILE_LAYER, OBJECT_LAYER.

  tiles = null              // Tile layer: Fully processed tiles.

  imageSrc = null           // Image layer: Image name.
  image = null              // Image layer: Image object.
  isParallax = false        // Image layer: Is this image used for parallax?
  parallaxMoveRatio = null  // Image layer (parallax only): Parallax move ratio.

  objects = null            // Object layer: Objects.
  objectsByName = null      // Object layer: Objects by name (object of arrays).
  objectsByType = null      // Object layer: Objects by type (object of arrays).
  objectsByTile = null      // Object layer: Objects by tile they occupy (object
                            // of objects; objectsByTile[x][y]).

  // Private fields.
  tileGIDs = null  // Global tile IDs.
  mapObj = null
  rawProperties = {}

  // Public.
  constructor(rawData, mapObj) {
    this.name = rawData.name
    this.mapObj = mapObj

    if (rawData.hasOwnProperty("properties")) {
      rawData.properties.forEach(e => {
        this.rawProperties[e.name] = e.value
      })
    }

    switch (rawData.type) {
      case "imagelayer":
        this.type = mapUtils.IMAGE_LAYER
        this.processImageLayer(rawData)
        break

      case "tilelayer":
        this.type = mapUtils.TILE_LAYER
        this.processTileLayer(rawData)
        break

      case "objectgroup":
        this.type = mapUtils.OBJECT_LAYER
        this.processObjectLayer(rawData)
        break

      default:
        throw "Unsupported layer type: " + rawData.type
    }
  }

  // Object layer only.
  getFirstObjectByName(name) {
    const objects = this.getObjectsByName(name)
    return objects.length > 0 ? objects[0] : null
  }

  getObjectsByName(name) {
    if (!this.objectsByName.hasOwnProperty(name)) {
      return []
    }

    return this.objectsByName[name]
  }

  getObjectsByType(type) {
    if (!this.objectsByType.hasOwnProperty(type)) {
      return []
    }

    return this.objectsByType[type]
  }

  getObjectsAtTile(x, y) {
    const yIndex = this.objectsByTile[x] || {}
    return yIndex[y] || []
  }

  // Private.
  processImageLayer(rawData) {
    this.mapObj.addResource({
      type: "image",
      name: rawData.image,
      path: `/bundle/${rawData.image}`
    })

    this.imageSrc = rawData.image

    if (rawData.name.startsWith("parallax")) {
      this.isParallax = true
      this.parallaxXMoveRatio = this.rawProperties.x_move_ratio
      this.parallaxYMoveRatio = this.rawProperties.y_move_ratio
    }
  }

  processTileLayer(rawData) {
    this.w = rawData.width
    this.h = rawData.height
    this.sz = rawData.width * rawData.height
    this.tileGIDs = this.base64ToUint32Array(rawData.data)
    this.tiles = new Array(this.tileGIDs.length)

    this.tileGIDs.forEach((tileGID, idx) => {
      if (tileGID != 0) {
        this.tiles[idx] = this.mapObj.globalTiles[tileGID]
      }
    })
  }

  processObjectLayer(rawData) {
    this.objects = utils.simpleDeepCopy(rawData.objects)

    // TODO: Probably all the indexing can be removed from the map as it's
    // being done in the state anyway (unless we want to keep "static" object
    // that are not converted to entities; but even so). Keep the property copy
    // though.
    this.objectsByName = {}
    this.objectsByType = {}
    this.objectsByTile = {}

    this.objects.forEach(obj => {
      this.indexIfPropertyExists(this.objectsByName, obj, "name")
      this.indexIfPropertyExists(this.objectsByType, obj, "type")
      this.indexByTile(this.objectsByTile, obj)

      if (obj.hasOwnProperty("properties")) {
        const properties = {}
        obj.properties.forEach(property => {
          properties[property.name] = property.value
        })
        obj.properties = properties
      }
    })
  }

  indexByTile(dstIndex, obj) {
    if (!obj.hasOwnProperty("x") || !obj.hasOwnProperty("y")) {
      return false
    }

    // TODO: this is broken - it only adds the object to the top-left-most tile,
    // where it should add it to all tiles the object occupies.
    // (in other words: it works fine for tile-aligned objects)

    const tileX = obj.x / this.mapObj.tileW | 0
    const tileY = obj.y / this.mapObj.tileH | 0
    obj.tileoffsetx = obj.x % this.mapObj.tileW
    obj.tileoffsety = obj.y % this.mapObj.tileH

    if (!dstIndex.hasOwnProperty(tileX)) {
      dstIndex[tileX] = {}
    }

    const dstYIndex = dstIndex[tileX]

    if (!dstYIndex.hasOwnProperty(tileY)) {
      dstYIndex[tileY] = []
    }

    dstYIndex[tileY].push(obj)
    return true
  }

  indexIfPropertyExists(dstIndex, obj, propertyName) {
    if (!obj.hasOwnProperty(propertyName)) {
      return false
    }

    const value = obj[propertyName]
    if (value.length === 0) {
      return false
    }

    if (!dstIndex.hasOwnProperty(value)) {
      dstIndex[value] = [obj]
    } else {
      dstIndex[value].push(obj)
    }

    return true
  }

  base64ToUint32Array(b64String) {
    let arr = null

    if (typeof Buffer !== "undefined") {
      // Node.js code.
      const bytes = Buffer.from(b64String, "base64")
      const dstSize = bytes.length / 4 | 0
      arr = new Uint32Array(dstSize)
      for (let i = 0; i < dstSize; i++) {
        arr[i] = bytes.readUInt32LE(i * 4)
      }
    }

    if (typeof atob !== "undefined") {
      // Browser code.
      const bytes = atob(b64String)
      const dstSize = bytes.length / 4 | 0
      arr = new Uint32Array(dstSize)
      for (let i = 0; i < dstSize; i++) {
        const srcIdx = i * 4
        arr[i] = (
          (bytes.charCodeAt(srcIdx + 0)) |
          (bytes.charCodeAt(srcIdx + 1) << 8) |
          (bytes.charCodeAt(srcIdx + 2) << 16) |
          (bytes.charCodeAt(srcIdx + 3) << 32)
        )
      }
    }

    return arr
  }
}

mapUtils.GameMap = class GameMap {
  mapUnprocessed = {}
  bundlePath = null
  layers = null
  resources = null
  tilesets = null
  framesets = null
  globalTiles = null  // Tiles indexed by GID.

  canvasW = null  // Tile layer width and height in pixels.
  canvasH = null
  tileW = null  // Single tile width and height in pixels.
  tileH = null
  columns = null  // Number of tiles horizontally and vertically.
  rows = null

  meta = {  // Configuration compiled from various map properties.
      // Note: Empty for now. TODO: remove if not useful in the end.
  }

  constructor() {
  }

  nodeLoad(bundle_path, fname) {
    this.mapUnprocessed = JSON.parse(
        fs.readFileSync(
            path.join(bundle_path, fname)
        )
    )
    this.processMap()
  }

  browserLoad(mapUnprocessed) {
    this.mapUnprocessed = mapUnprocessed
    this.processMap()
  }

  getUnprocessed() {
    return this.mapUnprocessed
  }

  getCollisionRectsForArea(x, y, w, h) {
    const areaTileX1 = x / this.tileW | 0
    const areaTileX2 = (x + w) / this.tileW | 0
    const areaTileY1 = y / this.tileH | 0
    const areaTileY2 = (y + h) / this.tileH | 0

    const rects = []

    Object.keys(this.layers).forEach(key => {
      if (!key.startsWith("fg")) {
        return
      }

      const layer = this.layers[key]
      for (let j = areaTileY1; j <= areaTileY2; j++) {
        for (let i = areaTileX1; i <= areaTileX2; i++) {
          const idx = i + j * this.columns
          const tile = layer.tiles[idx]

          if (!tile) {
            continue
          }

          const tileX = i * this.tileW
          const tileY = j * this.tileH

          tile.collisions.forEach(rect => {
            if (!rect.type) {
              rects.push([
                  tileX + rect.x, tileY + rect.y,
                  rect.width, rect.height
              ])
            }
          })
        }
      }
    })

    return rects
  }

  // Friend-classes only.
  addResource(res) {
    this.resources.push(res)
  }

  // Private.
  processMap() {
    this.resources = []

    this.tileW = this.mapUnprocessed.tilewidth
    this.tileH = this.mapUnprocessed.tileheight
    this.columns = this.mapUnprocessed.width
    this.rows = this.mapUnprocessed.height
    this.canvasW = this.tileW * this.columns
    this.canvasH = this.tileH * this.rows

    this.processTilesets()
    this.processLayers()
    this.compileMetadata()
  }

  compileMetadata() {
    // Note: Empty for now. TODO: remove if not useful in the end.
  }

  processLayers() {
    this.layers = {}

    this.mapUnprocessed.layers.forEach(layer => {
      this.layers[layer.name] = new mapUtils.MapLayer(layer, this)
    })
  }

  processTilesets() {
    this.tilesets = {}
    this.framesets = {}
    this.globalTiles = []

    this.mapUnprocessed.tilesets.forEach(tileset => {
      const tilesetObj = this.processTileset(tileset)

      if (tilesetObj.properties.is_frameset) {
        this.processFrameset(tilesetObj, tileset)
      }
    })
  }

  processFrameset(tilesetObj, tileset) {
    const framesetObj = new mapUtils.MapFrameset(tilesetObj, this)
    this.framesets[tileset.name] = framesetObj
    return framesetObj
  }

  processTileset(tileset) {
    const tilesetObj = new mapUtils.MapTileset(tileset, this)
    this.tilesets[tileset.name] = tilesetObj

    tilesetObj.tiles.forEach(e => {
      this.globalTiles[e.GID] = e
    })

    this.addResource({
      type: "image",
      name: tileset.image,
      path: `/bundle/${tileset.image}`
    })

    return tilesetObj
  }
}

// Node.js compliance.
if (typeof window === 'undefined') {
  global.fs = global.fs || require("fs")
  global.path = global.path || require("path")
  global.utils = global.utils || require("./utils")
  Object.assign(exports, mapUtils)
}
