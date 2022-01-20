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

const gameState = {}

// Desired max FPS, but also required number of logic recalculations per second.
gameState.TICKS_PER_SECOND = 60

// Helper values.
gameState.SEC_PER_TICK = 1 / gameState.TICKS_PER_SECOND
gameState.MS_PER_TICK = 1000 / gameState.TICKS_PER_SECOND | 0

// How long to keep history for new observers.
gameState.PERSISTENT_HISTORY_TICKS = gameState.TICKS_PER_SECOND * 600

// Lags happen. The following constant sets the maximum lag we allow for before
// disconnecting the player (in ticks).
gameState.MAX_BUFFERED_TICKS = (1.0 * gameState.TICKS_PER_SECOND) | 0

gameState.GameState = class GameState {
  map = null  // Game map to use.
  backendObjects = null  // Server-side only, not synchronized in any way.

  state = { // Game state (keep this JSON-serializable).
    tick: 0,  // Tick number.
    startTime: 0,  // Unix timestamp of first state.
    entities: {},  // Various objects, mobs, etc.
    meta: {  // Special state, persisted across saving and loading.
      challenges: {} // State and hashes of flags for challenges.
    },
    randState: utils.initDeterministicRandomState("GozGz"),
    auxiliaryInput: []  // Game-logic spawned input to be processed next time.
  }

  constructor(map, backendObjects=null) {
    this.map = map
    this.backendObjects = backendObjects
  }

  // Copy initial state from map settings.
  initialize(pc) {
    this.backendObjects.challenges.forEach(chal => {
      this.state.meta.challenges[chal.id] = {
        id: chal.id,
        solved: false
      }
    })

    // Spawn entites based on objects defined in the map data.
    const addedEntities = this.addEntities(this.map.layers.objects.objects)

    this.state.startTime = ((new Date()).getTime() / 1000) | 0
    if (pc.frameSet) {
      this.state.entities.player.frameSet = pc.frameSet
    }
  }

  duplicate() {
    const gs = new GameState(this.map, this.backendObjects)
    gs.state = utils.simpleDeepCopy(this.state)
    return gs
  }

  stateCopy() {
    return utils.simpleDeepCopy(this.state)
  }

  static fromJSON(jsonString, map=null) {
    const gs = new GameState(map)
    gs.state = JSON.parse(jsonString)
    return gs
  }

  // Note: This DOES NOT copy the stateDict object, it uses the provided object
  // as state.
  static fromStateDict(stateDict, map=null) {
    const gs = new GameState(map)
    gs.state = stateDict
    return gs
  }

  // fromDelta computes a new state from the previous state, the data that was modified
  // and the keys that were deleted. modified and deleted are the objects returned by
  // utils.computeDiff.
  static fromDelta(previousState, modified, deleted, map=null) {
    const newDict = utils.simpleDeepCopy(previousState.state)
    utils.mergeObjects(newDict, modified)
    utils.deleteKeys(newDict, deleted)
    return this.fromStateDict(newDict, map);
  }

  export() {
    return utils.computeDiff(this.state, this.oldState)
  }

  serialize() {
    return JSON.stringify(this.state)
  }

  static compare(stateA, stateB) {
    return utils.isEqual(stateA.state, stateB.state)
  }

  tick(input, consumedRngIds) {
    // Make a copy of the current state so that we can diff against it later.
    this.oldState = utils.simpleDeepCopy(this.state)

    this.state.tick++

    // Start with copying the auxiliary input (if any).
    while (this.state.auxiliaryInput.length > 0) {
      const auxInput = this.state.auxiliaryInput.shift()
      input[auxInput.type] = auxInput.value
    }

    // TODO: The player probably needs to either be calculated at the end, or
    // at the beginning as a special case (because the Player class might
    // run the "interact" handler).

    Object.entries(this.state.entities).forEach(e => {
      const entityClass = entities.classes[e[1].type]
      if (entityClass === undefined) {
        return
      }

      const tick = entityClass.tick
      if (tick === undefined) {
        return
      }
      tick.call(e[1], this, input, consumedRngIds)
    })
  }

  getNextEntityId() {
    var i = 0
    while(true) {
      if (this.state.entities[i] === undefined) {
        return i
      }
      i = i + 1
    }
  }

  // Returns a duplicate of the entity with the specified name. Modify the
  // object as needed, then call addEntity to instantiate it.
  duplicateEntity(name) {
    const map_objects = this.map.layers.objects.objects

    var i
    for(i = 0; i < map_objects.length; ++i) {
      if (map_objects[i].name === name) {
        var newEntity = utils.simpleDeepCopy(map_objects[i])
        var entityId = this.getNextEntityId()
        if (entityId == null) {
          return null;
        }
        newEntity.id = entityId
        delete newEntity.name
        return newEntity
      }
    }

    return null
  }

  removeEntity(id) {
    delete this.state.entities[id]
  }

  // Add a list of entities. Will first construct all entities,
  // then call .init() on all of them - it's therefore safe for the
  // .init() calls to refer to each other.
  addEntities(objs) {
    const ret = []
    for (let i = 0; i < objs.length; ++i) {
      const id_to_add = objs[i].name || `${objs[i].id}`
      if (this.state.entities[id_to_add] !== undefined) {
        console.error("Multiple entities with ID", id_to_add)
      }
      const entity = this._constructEntity(objs[i])
      ret.push(entity)
    }
    for (let j = 0; j < objs.length; ++j) {
      this._initializeEntity(ret[j], objs[j])
    }
    return ret
  }

  addEntity(obj) {
    const entity = this._constructEntity(obj)
    this._initializeEntity(entity, obj)

    return entity
  }

  _initializeEntity(entity, obj) {
    const entityClass = entities.classes[entity.type]
    if (entityClass && entityClass.init) {
      entityClass.init.call(entity, this, obj)
    }
  }

  _constructEntity(obj) {
    const entity = {
      type: obj.type,
      x: obj.x,
      y: obj.y,
      visible: obj.visible,
      id: obj.name || `${obj.id}`
    }

    // Get the frameset or fallback to a single tile.
    if (obj.properties && obj.properties.force_no_animation) {
      entity.tileGID = obj.gid
    } else {
      try {
        const tilesetName = this.map.globalTiles[obj.gid].tileset.name
        if (this.map.framesets[tilesetName]) {
          entity.frameSet = tilesetName
          entity.frameState = "default"
          entity.frame = 0
        } else {
          entity.tileGID = obj.gid
        }
      } catch (e) {
        console.error("Failed to process object", obj)
        throw e;
      }
    }

    if (obj.properties) {
      // Copy over some common properties
      if (obj.properties.visible !== undefined) {
        entity.visible = obj.properties.visible
      }
      if (obj.properties.collision !== undefined) {
        entity.collision = obj.properties.collision
      }
    }

    this.state.entities[entity.id] = entity
    return entity
  }

  // Returns a list of collision rectangles (x, y, w, h, type).
  getCollisionsRectsForTile(tile, p) {
    return tile.collisions.map(rect => [
        p[0] + rect.x,
        p[1] + rect.y,
        rect.width,
        rect.height,
        rect.type,
        rect.properties
    ])
  }

  rectsToBoundingBox(rects) {
    if (rects.length === 0) {
      return [-1, -1, 0, 0]
    }

    let x0 = rects[0][0]
    let y0 = rects[0][1]
    let x1 = x0 + rects[0][2]
    let y1 = y0 + rects[0][3]

    for (let i = 1; i < rects.length; ++i) {
      const rect = rects[i]
      if (rect[0] < x0) { x0 = rect[0] }
      if (rect[1] < y0) { y0 = rect[1] }
      if (rect[0] + rect[2] > x1) { x1 = rect[0] + rect[2] }
      if (rect[1] + rect[3] > y1) { y1 = rect[1] + rect[3] }
    }

    return [x0, y0, x1 - x0, y1 - y0]
  }

  getEntityCollisionRectsForArea(x, y, w, h, excludedEntities=[]) {
    const hardRects = []  // Collision rectangles of objects with .collision
                          // property set (i.e. impossible to pass through).
    const softRects = []  // Same, but for entities that can be passed through.

    const excludedEntitiesSet = new Set(excludedEntities)

    // TODO: Implement a decent structure to store the entities for fast
    // area enumeration. Like a quad-tree. Or even just tile-sized lookups.
    Object.entries(this.state.entities).forEach(entry => {
      const [entityID, e] = entry
      if (excludedEntitiesSet.has(entityID)) {
        return
      }

      // TODO: Maybe add support to entities that aren't tile based (e.g. shaped
      // that are supported by Tiled).

      const frameset = e.frameSet
      const tile = frameset ?
        this.map.framesets[frameset].getFrame(e.frameState, e.frame).tile :
        this.map.globalTiles[e.tileGID]

      if (!tile) {
        return
      }

      tile.collisions.forEach(c => {
        const rect = [e.x + c.x, e.y + c.y, c.width, c.height, entityID, c.type]

        if (x >= rect[0] + rect[2] || rect[0] >= x + w) {
          return
        }

        if (y >= rect[1] + rect[3] || rect[1] >= y + h) {
          return
        }

        if (e.collision) {
          hardRects.push(rect)
        } else {
          softRects.push(rect)
        }
      })
    })

    return [hardRects, softRects]
  }

  calculatePotentialMove(p, v, frame, excludedEntities) {
    // TODO: this whole stuff requires some "context" dict to cache stuff.
    // TODO: rework this to call getCollisionsRectsForTile only once.
    // (note: it's also called in iterateCollision. a lot.)

    const rectsOldPosition = this.getCollisionsRectsForTile(frame, p)
    const rectsNewPosition = this.getCollisionsRectsForTile(
        frame, [p[0] + v[0], p[1] + v[1]])

    const area = this.rectsToBoundingBox([
        ...rectsOldPosition, ...rectsNewPosition
    ])

    const mapRects = this.map.getCollisionRectsForArea(...area)
    const [hardRects, softRects] = this.getEntityCollisionRectsForArea(
        ...area, excludedEntities
    )
    mapRects.push(...hardRects)

    const [finalPosition, solidGround] = this.calculatePotentialMoveWorker(
        p, v, frame,
        rectsOldPosition, rectsNewPosition, mapRects
    )

    // TODO: calculatePotentialMoveWorker could return this
    const rectsFinalPosition = this.getCollisionsRectsForTile(
        frame, finalPosition
    )

    const collidingSoftEntities = {}
    this.getCollidingRects(softRects, rectsFinalPosition).forEach(rect => {
      const entityID = rect[4]
      const collisionType = rect[5]  // Collision rectangle's type property.
      if (collidingSoftEntities.hasOwnProperty(entityID)) {
        collidingSoftEntities[entityID].push(collisionType)
      } else {
        collidingSoftEntities[entityID] = [collisionType]
      }
    })

    return [finalPosition, solidGround, collidingSoftEntities]
  }

  calculatePotentialMoveWorker(
      p, v, frame, rectsOldPosition, rectsNewPosition, mapRects
  ) {
    // There is a possibility that due to frame change (and therefore hitbox
    // change) the entity is now stuck inside a tile or another entity. If
    // that's the case, attempt to fix the situation by teleporting the entity
    // to the nearest non-colliding location (do this instead of normal
    // movement).
    const [oldCollision, oldSolidGround] = this.checkMovementCollision(
        mapRects, rectsOldPosition
    )
    if (oldCollision) {
      // TODO: We need to get new map rects for the area 20 pixel wide
      // around the player.

      // Stuck.
      const vectors = [
        [0, 1], [0, -1], [-1, 0], [1, 0],
        [-1, 1], [1, 1], [-1, -1], [1, -1]
      ]

      // Look at most 20 pixels around to place the entity.
      for (let j = 1; j <= 20; j++) {
        for (let i = 0; i < 8; i++) {
          const candidateP = [
            (p[0] + vectors[i][0] * j)|0,
            (p[1] + vectors[i][1] * j)|0
          ]

          const entityRects = this.getCollisionsRectsForTile(frame, candidateP)
          let [candidateCollision, candidateSolidGround] = this.checkMovementCollision(
            mapRects, entityRects
          )

          if (!candidateCollision) {
            return [candidateP, candidateSolidGround]
          }
        }
      }

      console.log("it's stuck for good")

      return [p, oldSolidGround]
    }


    // Attempt to move the object the full requested vector.
    const maxMove = [p[0] + v[0], p[1] + v[1]]

    const [resultCollision, resultSolidGround] = this.checkMovementCollision(
        mapRects, rectsNewPosition
    )

    if (!resultCollision) {
      return [maxMove, resultSolidGround]
    }

    // Move the object as far as possible.
    const intPositions = this.getIntPositions(p, v)
    intPositions.pop()  // Skip end position.

    const [idx, solidGroundAtSafePosition] = this.iterateCollision(
        mapRects, intPositions, frame  // TODO: fix frame --> rects
    )
    const safePosition = (idx === null) ? p : intPositions[idx]

    // Slide the object either vertically or horizontally as far as possible.
    v[0] -= safePosition[0] - p[0]
    v[1] -= safePosition[1] - p[1]

    const intPositionsX = this.getIntPositions(safePosition, [v[0], 0])
    const intPositionsY = this.getIntPositions(safePosition, [0, v[1]])

    const [idxX, solidGroundAtIdxX] = this.iterateCollision(
        mapRects, intPositionsX, frame
    )

    const [idxY, solidGroundAtIdxY] = this.iterateCollision(
        mapRects, intPositionsY, frame
    )

    if (idxX === null && idxY === null) {
      if (solidGroundAtSafePosition === null) {
        // If safe position was defaulted to start position, we need to check
        // if there's solid ground there (can't reuse previous one since a
        // non-static object might have moved).
        const [resultCollision, resultSolidGround] = this.checkMovementCollision(
            mapRects, rectsOldPosition
        )
        return [safePosition, resultSolidGround]
      } else {
        return [safePosition, solidGroundAtSafePosition]
      }
    }

    if (idxX === null || (idxY !== null && idxY >= idxX)) {
      return [intPositionsY[idxY], solidGroundAtIdxY]
    }

    return [intPositionsX[idxX], solidGroundAtIdxX]
  }

  iterateCollision(mapRects, positions, frame) {
    if (positions.length == 0) {
      return [null, null]
    }

    let lastGood = null
    let lastGoodSolidGround = null

    for (let i = 0; i < positions.length; i++) {
      const entityRects = this.getCollisionsRectsForTile(frame, positions[i])
      let [resultCollision, resultSolidGround] = this.checkMovementCollision(
          mapRects, entityRects
      )

      if (resultCollision) {
        return [lastGood, lastGoodSolidGround]
      }

      lastGood = i
      lastGoodSolidGround = resultSolidGround
    }

    return [lastGood, lastGoodSolidGround]
  }

  getCollidingRects(mapRects, entityRects) {
    return mapRects.filter(a => {
      for (let b of entityRects) {
        if (a[0] >= b[0] + b[2] || b[0] >= a[0] + a[2]) {
          continue
        }

        if (a[1] >= b[1] + b[3] || b[1] >= a[1] + a[3]) {
          continue
        }

        return true
      }
      return false
    })
  }

  checkCollision(mapRects, entityRects) {
    let collisionTypes = new Set()

    for (let a of mapRects) {
      for (let b of entityRects) {
        if (a[0] >= b[0] + b[2] || b[0] >= a[0] + a[2]) {
          continue
        }

        if (a[1] >= b[1] + b[3] || b[1] >= a[1] + a[3]) {
          continue
        }

        if (b[5]["solid"]) {
          collisionTypes.add("solid")
        }

        if (b[4] !== "undefined" && b[4] !== "") {
          collisionTypes.add(b[4])
        }
      }
    }

    return collisionTypes
  }

  // Wrapper around checkCollision to preserve old return values.
  checkMovementCollision(mapRects, entityRects) {
    var collisionTypes = this.checkCollision(mapRects, entityRects)
    return [collisionTypes.has("solid"), collisionTypes.has("gravity")]
  }

  getIntPositions(p, v) {
    // Note: This function skips the initial integer position, but does include
    // the end position.
    const previous = [ p[0] | 0, p[1] | 0 ]

    const positions = []

    const length = Math.sqrt(v[0] * v[0] + v[1] * v[1])
    if (length >= 1.0) {
      const length2 = length * 2
      const nv = [ v[0] / length2, v[1] / length2 ]
      const it = [ p[0], p[1] ]
      const intLength2 = length2 | 0

      for (let i = 0; i < intLength2; i++, it[0] += nv[0], it[1] += nv[1]) {
        const intIt = [ it[0] | 0, it[1] | 0 ]
        if (intIt[0] === previous[0] && intIt[1] === previous[1]) {
          continue
        }

        positions.push([intIt[0], intIt[1]])

        previous[0] = intIt[0]
        previous[1] = intIt[1]
      }
    }

    const end = [p[0] + v[0], p[1] + v[1]]
    positions.push(end)

    return positions
  }
}

gameState.GameStateManager = class GameStateManager {
  // TODO: back end state verifier
  // NOTE: make sure to tick count! make sure that there is a tick limiter so
  // that between the connection start and current tick processing (and maybe
  // last tick?) enough time has passed (so that one doesn't just flood the
  // backend with ticks).

  currentState = null  // Newest fully verified state.
  backendObject = null
  stateHistory = null

  // Variables used to enforce rate limiting.
  connectionStartTime = null  // Time (ms) when current connection started.
  connectionStartTick = null  // Tick number at connection start.

  constructor(backendObject) {
    this.backendObject = backendObject
    this.stateHistory = []
  }

  addState(state) {
    if (this.stateHistory.length != state.state.tick) {
      throw ("New state tick number disagrees with state history size - " +
             "missing/extra states? length=" + this.stateHistory.length +
             " tick=" + state.state.tick)
    }
    this.stateHistory.push(state.stateCopy())
    if (this.stateHistory.length > gameState.PERSISTENT_HISTORY_TICKS) {
      this.stateHistory[this.stateHistory.length - gameState.PERSISTENT_HISTORY_TICKS - 1] = {
        tick: this.stateHistory.length - gameState.PERSISTENT_HISTORY_TICKS - 1,
        pruned: true
      }
    }
  }

  setCurrentState(stateDict, overwrite_meta) {
    console.log("setCurrentState", overwrite_meta)
    const meta = this.currentState.state.meta
    this.currentState.state = stateDict
    this.currentState.state.tick = this.stateHistory.length
    if (!overwrite_meta) {
      // Preserve meta across state changes
      this.currentState.state.meta = meta
    }

    this.addState(this.currentState)
  }

  setInitialState(state) {
    this.initialState = state.state
    this.currentState = state
    this.addState(state)
  }

  resetToInitialState() {
    this.setCurrentState(this.initialState)
  }

  getCurrentTick() {
    return this.currentState.state.tick
  }

  getSerializedState() {
    return this.currentState.serialize()
  }

  getState() {
    return this.currentState.stateCopy()
  }

  getHistoricState(tick) {
    if (tick >= this.stateHistory.length) {
      return this.stateHistory[this.stateHistory.length - 1]
    }

    return this.stateHistory[tick]
  }

  getHistoricStates(startTick, endTick) {
    return this.stateHistory.slice(startTick, endTick).map(x => x)
  }

  restartConnection() {
    this.connectionStartTime = Date.now()
    this.connectionStartTick = this.currentState.state.tick
  }

  processNewChanges(changes) {
    if (!Array.isArray(changes)) {
      return false
    }

    // TODO: if this doesn't work, j00ru proposes a sliding window.
    const now = Date.now()
    const maxPossibleTickNumber = (
          this.connectionStartTick +
          (now - this.connectionStartTime) * gameState.TICKS_PER_SECOND / 1000
        ) | 0

    while (changes.length > 0) {
      // Verify whether the tick doesn't exceed possible tick count.
      const expectedTick = this.currentState.state.tick + 1

      if (expectedTick > maxPossibleTickNumber) {
        // TODO: Debug stuff.
        console.error("Tick arrived too early.")
        return false
      }

      const change = changes.shift()
      if (!utils.isNonNullObject(change) || !utils.objectHasOwnProperty(change, "state") || !utils.objectHasOwnProperty(change, "inputs")) {
        return false
      }

      if (!utils.isNonNullObject(change.inputs)) {
        return false
      }

      const state = change.state
      if (!utils.isNonNullObject(state) || !utils.objectHasOwnProperty(state, "mod") || !utils.objectHasOwnProperty(state, "del")) {
        return false
      }

      const {mod, del} = state
      if (!utils.isNonNullObject(mod) || !utils.isNonNullObject(del)) {
        return false
      }

      const proposedState = gameState.GameState.fromDelta(this.currentState.duplicate(), mod, del)
      const simulatedState = this.currentState.duplicate()
      simulatedState.tick(change.inputs, change.consumedRngIds)

      if (proposedState.state.tick != simulatedState.state.tick) {
        console.error("Expected state with tick ", simulatedState.state.tick,
          " but received state with tick ", proposedState.state.tick,
          "- this usually indicates an exception on the client side made it skip a tick.")
        return false
      }
      if (!gameState.GameState.compare(proposedState, simulatedState)) {
        // TODO: Debug stuff.
        console.error("State mismatch. Proposed:")
        console.log(JSON.stringify(proposedState.state, null, 2))
        console.log("Simulated:")
        console.log(JSON.stringify(simulatedState.state, null, 2))
        console.log("Diff:")
        console.log(JSON.stringify(utils.computeDiff(proposedState.state, simulatedState.state)))
        return false
      }

      this.currentState = simulatedState
      this.addState(this.currentState)
    }

    return true
  }
}

// Node.js compliance.
if (typeof window === 'undefined') {
  global.utils = global.utils || require("./utils")
  global.entities = global.entities || require("./entities")
  Object.assign(exports, gameState)
}
