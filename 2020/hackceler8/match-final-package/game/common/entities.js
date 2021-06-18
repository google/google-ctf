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

const entities = {}
entities.classes = {}  // Note: This is called "type" in various places.
entities.animationEngines = {}  // Engine is too big of a word here.

// Important: Entities must have only JSON-serializable properties, as they are
// part of game state.

// Entity classes can optionally implement the following static methods.
//
//   init(state, entity, data):
//     Called when creating an entity of this class.
//       Arguments:
//         state: GameState object.
//         data: Entity class specific initialization data.
//         *this: Entity instance properties (must be JSON-serializable).
//
//   tick(state, entity, input):
//     Called on every tick.
//       Arguments:
//         state: GameState object.
//         input: Player input (if any).
//         *this: Entity instance properties (must be JSON-serializable).
//

// Entity instances must have the following fields.
//
//   type: String name of the entity class.
//   x, y: Entity coordinates.
//   visible: Whether the entity should be rendered.
//   id: Entity ID, used e.g. in state.entities object.
//
//   For animated entities:
//     frameSet: Name of the frameset to be used for animation.
//     frameState: Name of animation state.
//     frame: Frame counter in the animation.
//
//   For non-animated entities:
//     tileGID: Global ID of the tile to use.
//
//   Optional properties:
//     flipImage: If true, flips the image horizontally.
//

entities.classes.Block = class Block {
  static init(state, data) {
    this.collision = true
  }
}

entities.classes.Sign = class Sign {
  static init(state, data) {
    this.text = data.properties.text
    this.showing = false
    this.interacting = false
  }

  static tick() {
    if (!this.interacting) {
      this.showing = false
    }

    this.interacting = false
  }

  static interact(state, input, types) {
    this.interacting = true
    if ("down" in input) {
      if (!this.showing) {
        console.log(this.text)
        this.showing = true
      }
    } else {
      this.showing = false
    }
  }
}

entities.classes.Player = class Player {
  static init(state, data) {
    // The following properties should be initialized by map loader / state
    // initialization routine:
    //   x, y: Player position.
    //   frameSet: Player animation frameset.

    // Setup remaining properties.
    this.visible = true           // Is the player visible?
    this.solidGround = false      // Does the player stand on solid ground?
    this.canJump = false          // Can the player jump?
    this.jumpV = 0                // Jump/fall velocity.
    this.moveV = 0                // Horizontal movement velocity.
    this.heldEntityId = null      // Item currently held in hand

    // Initialize animation properties:
    //   frameState:  Animation state.
    //   frame:  Animation frame.
    entities.animationEngines.Character.init.call(this, state, data)
  }

  static death(state) {
    const DEATH_PENALTY = 10 // Seconds.

    this.dead = true
    this.respawnTick =
        state.state.tick +
        gameState.TICKS_PER_SECOND * DEATH_PENALTY

    const respawnPoints = state.map.layers.metadata.getObjectsByType("respawn")
    const pX = this.x
    const pY = this.y
    let minDistanceSq = Infinity
    let closestRespawn = null

    respawnPoints.forEach(respawn => {
      const diffX = pX - respawn.x
      const diffY = pY - respawn.y
      const distanceSq = diffX * diffX + diffY * diffY
      if (distanceSq < minDistanceSq) {
        minDistanceSq = distanceSq
        closestRespawn = respawn
      }
    })

    this.respawnPoint = [
      closestRespawn.x,
      closestRespawn.y
    ]

    this.pickupLatch = false
  }

  static tick(state, input) {
    // TODO: Move these constants somewhere.
    const maxMovementSpeed = 180 * gameState.SEC_PER_TICK
    const accelerationSpeed = 15 * gameState.SEC_PER_TICK
    const stopSpeed = 17 * gameState.SEC_PER_TICK

    const pushGravity = 1

    const gravity = 26 * gameState.SEC_PER_TICK
    const maxFallSpeed = 400 * gameState.SEC_PER_TICK

    const initialJumpSpeed = 460 * gameState.SEC_PER_TICK

    if (state.state.victory) {
      return
    }

    if (this.dead) {
      if (state.state.tick >= this.respawnTick) {
        // Teleport the player to the respawn point.
        this.x = this.respawnPoint[0]
        this.y = this.respawnPoint[1]

        // Reset player's vector.
        this.moveV = 0
        this.jumpV = 0

        // Stop being dead.
        delete this.dead
        delete this.respawnTick
        delete this.respawnPoint
      } else {
        // TODO: Maybe add animation ticking, and add death animation to the
        // animation engine.
        return
      }
    }

    const currentX = this.x
    const currentY = this.y

    if ("death" in input) {
      Player.death.call(this, state)
      return
    }

    if ("right" in input) {
      if (this.moveV < 0) {
        this.moveV = 0  // Reset to 0 if was going the other way.
      }

      this.moveV = Math.min(
          maxMovementSpeed, this.moveV + accelerationSpeed
      )
    } else if ("left" in input) {
      if (this.moveV > 0) {
        this.moveV = 0  // Reset to 0 if was going the other way.
      }

      this.moveV = Math.max(
          -maxMovementSpeed, this.moveV - accelerationSpeed
      )
    } else {
      if (this.moveV > 0) {
        this.moveV = Math.max(0, this.moveV - stopSpeed)
      } else {
        this.moveV = Math.min(0, this.moveV + stopSpeed)
      }
    }

    // Allow jumps only if the player is on the ground at least one tick without
    // holding the UP arrow.
    if (!this.canJump && this.solidGround && !("up" in input)) {
      this.canJump = true
    }

    if (this.canJump && !this.solidGround) {
      this.canJump = false
    }

    if (this.canJump) {
      this.jumpV = pushGravity  // Push player into the ground.

      if ("up" in input) {
        this.jumpV = -initialJumpSpeed
      }

    } else {
      this.jumpV = Math.min(maxFallSpeed, this.jumpV + gravity)
    }

    if ("down" in input) {
      // TODO ???
    }

    // Tick the animation engine to potentially update the frame.
    entities.animationEngines.Character.tick.call(this, state)

    const currentFrame = state.map.framesets[this.frameSet].getFrame(
        this.frameState, this.frame
    )

    // TODO: calculatePotentialMove should actually both get the frame,
    // and return whether "gravity" collision was hit.
    const [
        newPosition, solidGround, collidingEntities
    ] = state.calculatePotentialMove(
        [currentX, currentY],
        [this.moveV, this.jumpV],
        currentFrame.tile,
        [this.id]  // Exclude this entity from colliding with itself.
    )

    this.x = newPosition[0]
    this.y = newPosition[1]
    this.solidGround = solidGround

    // In case it wasn't possible to move vertically the whole way, cut the
    // jump velocity.
    // TODO: Just return the case from calculatePotentialMove instead of this
    // check.
    if (this.y !== currentY + this.jumpV && this.jumpV < 0) {
      this.jumpV = 0
    }

    // Death awaits below the map.
    if (this.y > state.map.canvasH) {
      state.killPlayer()
    }

    // Death awaits in death zones.
    const deathZones = state.map.layers.metadata.getObjectsByType("death")
    for (let i = 0; i < deathZones.length; i++) {
      const deathZone = deathZones[i]
      if (this.x >= deathZone.x && this.x < deathZone.x + deathZone.width &&
          this.y >= deathZone.y && this.y < deathZone.y + deathZone.height) {
        state.killPlayer()
      }
    }

    if (!input.pickup) {
      this.pickupLatch = false
    }

    if (input.pickup && !this.pickupLatch && this.heldEntityId !== null) {
      // We're already holding an entity, so put it down
      const entityID = this.heldEntityId
      const entity = state.state.entities[entityID]

      if (entity) {
        const entityClass = entities.classes[entity.type]

        if (entityClass) {
          const putdown = entityClass.putdown
          if (putdown) {
            putdown.call(entity, state, input)
          }
        }
        this.heldEntityId = null
        this.pickupLatch = true
        entity.y = entity.y + 48
      }
    }

    // For all collidingEntities, call the interaction handlers.
    Object.entries(collidingEntities).forEach(e => {
      const [entityID, collisionTypes] = e
      const entity = state.state.entities[entityID]
      const entityClass = entities.classes[entity.type]

      if (entityClass === undefined) {
        return
      }

      const interact = entityClass.interact
      if (interact === undefined) {
        return
      }

      interact.call(entity, state, input, collisionTypes)
    })

    // If we're picking an item up, find the first colliding entity that is
    // pickup-able, and pick it up
    if (input.pickup && !this.pickupLatch) {
      Object.entries(collidingEntities).forEach(e => {
        if (this.pickupLatch) {
          return
        }

        const [entityID, collisionTypes] = e
        const entity = state.state.entities[entityID]
        const entityClass = entities.classes[entity.type]

        if (!entity.pickupAble) {
          return
        }

        this.heldEntityId = entityID
        this.pickupLatch = true

        const pickup = entityClass.pickup
        if (pickup === undefined) {
          return
        }

        if (entityClass === undefined) {
          return
        }

        pickup.call(entity, state, input, collisionTypes)
      })
    }

    // If we're holding an item, render it above our heads
    if (this.heldEntityId !== null) {
      const entity = state.state.entities[this.heldEntityId]
      if (entity) {
        entity.x = this.x + 32
        if (entity.pickupHeight) {
          entity.y = this.y - entity.pickupHeight
        } else {
          entity.y = this.y
        }
      }
    }
  }
}

entities.animResetFrameInfo = function(anim, state) {
  const frames = state.map.framesets[anim.frameSet].getFrames(anim.frameState)
  anim.frame = 0
  anim.animStartTick = state.state.tick
  anim.animFrameCount = frames.length
  anim.animFrameDuration = (frames[0].duration / gameState.MS_PER_TICK)|0
}

entities.animTickFrame = function(anim, state) {
  const now = state.state.tick
  const ticksDiff = now - anim.animStartTick

  if (ticksDiff < anim.animFrameDuration) {
    return false
  }

  // Go to next frame.
  const frames = state.map.framesets[anim.frameSet].getFrames(anim.frameState)
  anim.animStartTick = now
  anim.frame = (anim.frame + 1) % anim.animFrameCount
  const endOfFrames = (anim.frame === 0)
  anim.animFrameDuration = (frames[anim.frame].duration /
                            gameState.MS_PER_TICK)|0

  return endOfFrames
}

entities.animationEngines.Simple = class Simple {
  static init(state) {
    this.frameState = "default"
    entities.animResetFrameInfo(this, state)
  }

  static tick(state) {
    entities.animTickFrame(this, state)
  }
}

entities.animationEngines.Character = class Character {
  static init(state) {
    this.frameState = "standing"
    entities.animResetFrameInfo(this, state)
  }

  static tick(state) {
    const endOfFrames = entities.animTickFrame(this, state)

    // A state machine.
    let newState = null
    switch (this.frameState) {
      case "standing":
        if (this.jumpV < 0) {
          newState = "jump_starting"
        } else if (!this.solidGround && this.jumpV > 0) {
          newState = "jump_flying"
        } else if (this.moveV !== 0) {
          newState = "running"
        }
        break

      case "jump_starting":
        if (endOfFrames) {
          newState = "jump_flying"
        }
        break

      case "jump_flying":
        if (this.solidGround) {
          newState = "jump_landing"
        }
        break

      case "jump_landing":
        if (this.moveV !== 0) {
          newState = "running"
        } else if (endOfFrames) {
          newState = "standing"
        }
        break

      case "running":
        if (this.jumpV < 0) {
          newState = "jump_starting"
        } else if (!this.solidGround && this.jumpV > 0) {
          newState = "jump_flying"
        } else if (this.moveV === 0) {
          newState = "standing"
        }
        break
    }

    if (newState) {
      this.frameState = newState
      entities.animResetFrameInfo(this, state)
    }

    if (this.moveV > 0) {
      this.flipImage = false
    } else if (this.moveV < 0) {
      this.flipImage = true
    }  // Else leave as is.
  }
}

entities.classes.FlagConsole = class FlagConsole {
  static init(state, data) {
    this.interacting = false
    this.showing = false
    this.challengeID = data.properties.challenge_id
    this.value = ""  // Holds unsubmitted flag values
    this.pickupAble = true
    this.pickupHeight = 48

    entities.animationEngines.Simple.init.call(this, state, data)
  }

  static tick(state, input) {
    entities.animationEngines.Simple.tick.call(this, state)

    if (this.showing && !this.interacting) {
      this.showing = false

      if (!state.backendObjects) {
        // Browser.
        const flagUI = globals.game.getFlagConsoleUIObject(this.challengeID)
        flagUI.hide()
      }
    }

    this.interacting = false

    // This input occurs when a user types into the flag box. Set the value
    // field.
    if ("setFlag" in input) {
      const challengeId = input.setFlag[0]
      const value = input.setFlag[1]
      if (challengeId == this.challengeID) {
        this.value = value
      }
    }
  }

  static interact(state, input, types) {
    this.interacting = true

    const challengeState = state.state.challenges[this.challengeID]

    if (this.showing && "escape" in input) {
      this.showing = false

      if (!state.backendObjects) {
        // Browser.
        const flagUI = globals.game.getFlagConsoleUIObject(this.challengeID)
        flagUI.hide()
      }
    }

    if (!this.showing && "down" in input) {
      this.showing = true

      if (!state.backendObjects) {
        // Browser.
        const flagUI = globals.game.getFlagConsoleUIObject(this.challengeID)
        flagUI.setStatus(challengeState.solved ? "solved" : "start")
        flagUI.show()
      }
    }

    if ("flag" in input && !challengeState.solved) {
       // Changes here are irreversible.
      const flag = input.flag[0]

      if (state.backendObjects) {
        // Backend.
        const hash = crypto.createHash("sha256")
        hash.update(flag)
        const flagHash = hash.digest("hex")

        const correctHash =
            state.backendObjects.challengeIndex.get(this.challengeID).flag

        if (flagHash === correctHash) {
          challengeState.solved = true
          const now = ((+new Date()) / 1000) | 0
          console.warn(`----- challenge ${this.challengeID} solved at ${now}`)

          const d = `${now}:${this.challengeID}\n`
          fs.appendFile("solved.txt", d, err => {
            if (err) {
              console.error('failed to save solved')
            } else {
              console.log('solved saved')
            }
          })
        }
      } else {
        // Browser.
        const flagUI = globals.game.getFlagConsoleUIObject(this.challengeID)
        const flagCorrect = input.flag[1]

        if (flagCorrect) {
          challengeState.solved = true
          flagUI.setStatus("good")
        } else {
          flagUI.setStatus("fail")
        }
      }
    }
  }
}

entities.classes.Terminal = class Terminal {
  static init(state, data) {
    this.interacting = false
    this.showing = false
    this.properties = data.properties
    this.challengeID = data.properties.challenge_id

    entities.animationEngines.Simple.init.call(this, state, data)
  }

  static tick(state) {
    entities.animationEngines.Simple.tick.call(this, state)

    if (this.showing && !this.interacting) {
      this.showing = false

      if (!state.backendObjects) {
        // Browser.
        const terminalUI = globals.game.getTerminalUIObject(this.challengeID)
        terminalUI.hide()
      }
    }

    this.interacting = false
  }

  static interact(state, input, types) {
    this.interacting = true

    if (this.showing && "escape" in input) {
      this.showing = false

      if (!state.backendObjects) {
        // Browser.
        const terminalUI = globals.game.getTerminalUIObject(this.challengeID)
        terminalUI.hide()
      }
    }

    if (!this.showing && "down" in input) {
      this.showing = true

      if (state.backendObjects) {
        // Backend.
        state.backendObjects.connectors[this.challengeID].write("")
      } else {
        // Browser.
        const terminalUI = globals.game.getTerminalUIObject(this.challengeID)
        terminalUI.show()
      }
    }

    if ("terminal" in input) {
       // Changes here are irreversible.
      const dataHexEncoded = input.terminal
      if (state.backendObjects) {
        // Backend.
        const data = Buffer.from(dataHexEncoded, "hex")
        state.backendObjects.connectors[this.challengeID].write(data)
      } else {
        // Browser.
        const terminalUI = globals.game.getTerminalUIObject(this.challengeID)
        const data = utils.hexToUint8Array(dataHexEncoded)
        const text = utils.textDecoder.decode(data)
        terminalUI.appendOutput(text)
      }
    }
  }
}

entities.classes.Control = class Control {
  static init(state, data) {
    if (data.properties.door_toggle) {
      this.doors = data.properties.door_toggle.split(";")
    } else {
      this.doors = []
    }

    if (data.properties.spawn) {
      this.spawn = data.properties.spawn
      this.randState = utils.initDeterministicRandomState(data.properties.toString())
    } else {
      this.spawn = null
    }

    // Animation stuff
    this.frameState = "unpushed_0"
    if (data.properties.value !== undefined) {
      this.frameState = "unpushed_" + data.properties.value
    }
    const frames = state.map.framesets[this.frameSet].getFrames(this.frameState)
    this.frame = 0
    this.animStartTick = state.state.tick
    this.animFrameCount = frames.length
    this.animFrameDuration = (frames[0].duration / gameState.MS_PER_TICK)|0

  }

  static interact(state, input, types) {
    if ("down" in input) {
      if (this.interacting) return;
      if (this.tickdown !== undefined) return;
      this.interacting = true;


      // Code for opening/closing attached doors
      var i
      for (i = 0; i < this.doors.length; ++i) {
        const door_id = this.doors[i]
        const new_door = entities.actuateDoor(state, door_id)
        if (new_door !== null) {
          this.doors[i] = new_door;
        }
      }

      // Code for spawning specified item
      if (this.spawn) {
        var new_entity = state.duplicateEntity(this.spawn)
        if (new_entity !== null) {
          var offsetX = utils.deterministicRandom(this.randState)
          var offsetY = utils.deterministicRandom(this.randState)
          new_entity.x = this.x + 48 + (offsetX % 16)
          new_entity.y = this.y + 24 + (offsetY % 16)
          state.addEntity(new_entity)
        }
      }

      // Animation stuff
      this.tickdown = 5
      this.frameState = this.frameState.slice(2)
      const frames = state.map.framesets[this.frameSet].getFrames(this.frameState)
      this.frame = 0
      this.animStartTick = state.state.tick
      this.animFrameCount = frames.length
      this.animFrameDuration = (frames[0].duration / gameState.MS_PER_TICK)|0
    } else {
      this.interacting = false;
    }
  }

  static tick(state) {
    if (this.tickdown) {
      this.tickdown = this.tickdown - 1
      if (this.tickdown == 0) {
        delete this.tickdown
        this.frameState = "un" + this.frameState
        const frames = state.map.framesets[this.frameSet].getFrames(this.frameState)
        this.frame = 0
        this.animStartTick = state.state.tick
        this.animFrameCount = frames.length
        this.animFrameDuration = (frames[0].duration / gameState.MS_PER_TICK)|0
      }
    }
    entities.animationEngines.Simple.tick.call(this, state)
  }
}

entities.classes.KeyReceptacle = class KeyReceptacle {
  static init(state, data) {
    this.collision = true
    this.holds_key = false
    this.tickdown = null
    if (data.properties.door_toggle) {
      this.doors = data.properties.door_toggle.split(";")
    } else {
      this.doors = []
    }

    this.frameState = "locked_0"
    entities.animationEngines.Simple.init.call(this, state, data)

    if (data.properties.value !== undefined) {
      this.value = data.properties.value
      this.frameState = "locked_" + this.value
      entities.animResetFrameInfo(this, state)
    } else {
      console.warn("KeyReceptacle is missing value property.")
      this.value = null
    }
  }

  static tick(state) {
    const did_hold_key = this.holds_key
    this.holds_key = false

    const player = state.state.entities.player
    for (const id in state.state.entities) {
      if (id == this.id) { continue }

      const key = state.state.entities[id]
      // The logic here is a bit... confusing.
      if (key.value === undefined) { continue }
      if (key.value != this.value) { continue }
      if (player.heldEntityId == id) { continue }
      if (key.x < this.x - 16) { continue }
      if (key.x > this.x + 96) { continue }
      if (key.y < this.y - 96) { continue }
      if (key.y > this.y + 32) { continue }

      this.holds_key = true
      key.x = this.x + 16
      key.y = this.y
    }

    if (did_hold_key != this.holds_key) {
      if (this.holds_key) {
        this.frameState = "unlocked_" + this.value
        this.tickdown = gameState.TICKS_PER_SECOND / 2
      } else {
        this.frameState = "locked_" + this.value
        if (this.tickdown == 0) {
          // The key was in the receptacle long enough to activate, de-activate.
          var i
          for (i = 0; i < this.doors.length; ++i) {
            const door_id = this.doors[i]
            const new_door = entities.actuateDoor(state, door_id)
            if (new_door !== null) {
              this.doors[i] = new_door;
            }
          }
        }
      }
      entities.animResetFrameInfo(this, state)
    }

    if (this.holds_key && this.tickdown) {
      this.tickdown = this.tickdown - 1
      if (this.tickdown == 0) {
        // Once the key has been in the receptacle long enough for the animation
        // to play, open attached doors.
        var i
        for (i = 0; i < this.doors.length; ++i) {
          const door_id = this.doors[i]
          this.doors[i] = entities.actuateDoor(state, door_id)
        }
      }
    }

    entities.animationEngines.Simple.tick.call(this, state)
  }
}

entities.classes.Key = class Key {
  static init(state, data) {
    this.pickupAble = true
    this.pickupHeight = 16
    if (data.properties.value !== undefined) {
      this.value = data.properties.value
    } else {
      this.value = null
    }
  }
}

entities.classes.ClosedDoor = class ClosedDoor {
  static init(state, data) {
    this.collision = true
  }

  static interact(state, input, types) {
  }
}

entities.classes.OpenDoor = class OpenDoor {
  static init(state, data) {
  }

  static interact(state, input, types) {

  }
}

entities.animationEngines.OneWay = class OneWay {
  static init(state) {
    this.frameState = "default"
    entities.animResetFrameInfo(this, state)
  }

  static tick(state, animProps) {
    const endOfFrames = entities.animTickFrame(this, state)

    let newState = null
    if (this.collision) {
      if (this.frameState === "default") {
        return
      }

      this.frameState = "default"
      entities.animResetFrameInfo(this, state)
      return
    }

    if (this.frameState === this.direction) {
      return
    }

    this.frameState = this.direction
    entities.animResetFrameInfo(this, state)
  }
}

entities.classes.OneWay = class OneWay {
  static init(state, data) {
    this.direction = state.map.globalTiles[data.gid].properties.direction
    this.collision = true

    entities.animationEngines.OneWay.init.call(this, state)
  }

  static getEntityBB(state, e) {
    // Note: It uses only the first collision in the list.
    const frameset = e.frameSet
    const tile = frameset ?
        state.map.framesets[frameset].getFrame(e.frameState, e.frame).tile :
        state.map.globalTiles[e.tileGID]

    const c = tile.collisions[0]
    return [
      e.x + c.x | 0,
      e.y + c.y | 0,
      e.x + c.x + c.width | 0,
      e.y + c.y + c.height | 0
    ]
  }

  static tick(state) {
    const player = state.state.entities.player
    const [pX1, pY1, pX2, pY2] = OneWay.getEntityBB(state, player)
    const [eX1, eY1, eX2, eY2] = OneWay.getEntityBB(state, this)

    // Logic is the following:
    // If the player is on the one-way entity, do no changes (null).
    // Disable collision if the player is on the "before" side of the entity.
    // And enable it if the player is on the "after" side of the entity.
    let shouldCollide = null
    switch (this.direction) {
      case "right":
        shouldCollide = (pX1 > eX2) ? true : (pX2 <= eX2) ? false : null
        break

      case "left":
        shouldCollide = (pX2 >= eX2) ? false : (pX2 < eX1) ? true : null
        break

      case "up":
        shouldCollide = (pY2 >= eY2) ? false : (pY2 < eY1) ? true : null
        break

      case "down":
        shouldCollide = (pY1 > eY2) ? true : (pY2 <= eY2) ? false : null
        break
    }

    if (shouldCollide !== null) {
      this.collision = shouldCollide
    }

    entities.animationEngines.OneWay.tick.call(this, state)
  }
}

entities.animationEngines.Portal = class Portal {
  static init(state) {
    this.frameState = "default"
    entities.animResetFrameInfo(this, state)
  }

  static tick(state) {
    if (this.open &&
        this.frameState !== "open" &&
        this.frameState !== "opening") {
      this.frameState = "opening"
      entities.animResetFrameInfo(this, state)
    }

    const endOfFrames = entities.animTickFrame(this, state)
    if (endOfFrames && this.frameState === "opening") {
      this.frameState = "open"
      entities.animResetFrameInfo(this, state)
      entities.animTickFrame(this, state)
    }
  }
}

entities.classes.Portal = class Portal {
  static init(state, data) {
    this.open = false
    this.requiredOrbs =
        data.properties.required_orbs.split("\n")
        .map(e => e.trim())
        .filter(e => e.length)

    if (this.requiredOrbs.length === 0) {
      this.open = true
    }

    const target = data.properties.target
    if (target) {
      this.target =
          state.map.layers.metadata.getObjectsByName(target)
          .filter(e => e.type === "portal_target")[0]

      if (!this.target) {
        console.warn(`Failed to find portal target: ${target}`)
      }
    } else {
      this.target = null
    }

    entities.animationEngines.Portal.init.call(this, state, data)
  }

  static tick(state) {
    if (!this.open) {
      const challenges = state.state.challenges
      if (this.requiredOrbs.every(e => challenges[e].solved)) {
        this.open = true
      }
    }

    entities.animationEngines.Portal.tick.call(this, state)
  }

  static interact(state, input, types) {
    if (!this.open) {
      return
    }

    if ("down" in input && this.target) {
      // TODO: Perhaps this should be moved to player.teleport() or sth.
      const player = state.state.entities.player
      player.x = this.target.x
      player.y = this.target.y

      // Reset player's vector.
      player.moveV = 0
      player.jumpV = 0
    }
  }
}

entities.classes.CounterDoor = class CounterDoor {
  static init(state, data) {
    this.collision = true
    this.requiredOrbs =
        data.properties.required_orbs.split("\n")
        .map(e => e.trim())
        .filter(e => e.length)
  }

  static tick(state) {
    if (!this.open) {
      const challenges = state.state.challenges
      if (this.requiredOrbs.every(e => challenges[e].solved)) {
        entities.actuateDoor(state, this.id)
      }
    }
  }
}

entities.animationEngines.Escape = class Escape {
  static init(state) {
    this.frameState = "default"
    entities.animResetFrameInfo(this, state)
  }

  static tick(state) {
    if (this.startTeleporting) {
      this.startTeleporting = false
      this.frameState = "teleport"
      entities.animResetFrameInfo(this, state)
    }

    const endOfFrames = entities.animTickFrame(this, state)
    if (endOfFrames && this.frameState === "teleport") {
      this.frameState = "default"
      entities.animResetFrameInfo(this, state)
      entities.animTickFrame(this, state)
    }
  }
}

entities.classes.Escape = class Escape {
  static init(state, data) {
    this.startTeleporting = false
    entities.animationEngines.Escape.init.call(this, state, data)
  }

  static tick(state) {
    entities.animationEngines.Escape.tick.call(this, state)
  }

  static interact(state, input, types) {
    if (!state.state.victory) {
      const challenges = Object.entries(state.state.challenges)
      if (!challenges.every(e => e[1].solved)) {

        if (!state.backendObjects && state.state.tick % 60 == 0) {
          console.log("Go solve challenges.")
        }

        return
      }

      state.state.victory = true
      this.startTeleporting = true

      const now = ((+new Date()) / 1000) | 0
      console.warn(`----- ESCAPE at ${now}`)

      if (state.backendObjects) {
        const d = `${now}:escape\n`
        fs.appendFile("solved.txt", d, err => {
          if (err) {
            console.error("failed to save escape")
          } else {
            console.log("escape saved")
          }
        })
      }
    }
  }
}

entities.actuateDoor = function(state, door_id) {
const door = state.state.entities[door_id]
  if (!door) {
    return null
  }

  var new_id = null

  if (door.type === "ClosedDoor" || door.type === "CounterDoor") {
    var new_door = state.duplicateEntity("door_open_template")
    if (new_door !== null) {
      new_door.x = door.x
      new_door.y = door.y
      new_id = new_door.id
      state.addEntity(new_door)
    }

    state.removeEntity(door_id)
  } else if (door.type === "OpenDoor") {
    var new_door = state.duplicateEntity("door_closed_template")
    if (new_door !== null) {
      new_door.x = door.x
      new_door.y = door.y
      new_id = new_door.id
      state.addEntity(new_door)
    }
    state.removeEntity(door_id)
  } else {
    console.warn("Door should have type ClosedDoor or OpenDoor, got door with type " + door.type)
    return null
  }
  return new_id
}

entities.classes.Exploder = class Exploder {
  static init(state, data) {
    this.pickupAble = true
    this.pickupHeight = 4
    this.frameState = "default"
    entities.animationEngines.Simple.init.call(this, state, data)
  }

  static interact(state, input, types) {
    if ("down" in input) {
      state.removeEntity(this.id)
      var newEntity = state.duplicateEntity("exploding_exploder_template")
      newEntity.x = this.x
      newEntity.y = this.y
      state.addEntity(newEntity)
    }
  }

  static tick(state) {
    entities.animationEngines.Simple.tick.call(this, state)
  }
}

entities.classes.ExplodingExploder = class ExplodingExploder {
  static init(state, data) {
    //this.pickupAble = true  // We fixed the glitch
    //this.pickupHeight = 4
    this.frameState = "default"
    this.startTick = state.state.tick
    entities.animationEngines.Simple.init.call(this, state, data)
  }

  static tick(state) {
    if (this.id == "exploding_exploder_template") {
      return;
    }

    entities.animationEngines.Simple.tick.call(this, state)
    const tickCount = state.state.tick - this.startTick
    if (tickCount >= 30) {
      for (const id in state.state.entities) {
        const wall = state.state.entities[id]
        if (wall.type != "CrackedWall") { continue; }

        const wallCenterX = wall.x + 16
        const wallCenterY = wall.y + 48
        const thisCenterX = this.x + 8
        const thisCenterY = this.y - 32

        if (Math.abs(thisCenterY - wallCenterY) > 96) continue;
        if (Math.abs(thisCenterX - wallCenterX) > 96) continue;


        state.removeEntity(id)
      }

      if (typeof document !== "undefined") {
        const game = document.getElementById("game")
        game.style.removeProperty("filter")
      }
      state.removeEntity(this.id)
      return
    }

    if (typeof document !== "undefined") {
      const game = document.getElementById("game")
      game.style.filter = "blur(" + (tickCount * 2) + "px) brightness(" + (tickCount / 2) + ")"
    }
  }
}

entities.classes.CrackedWall = class CrackedWall {
  static init(state, data) {
    this.collision = true
  }
}

// Node.js compliance.
if (typeof window === 'undefined') {
  global.crypto = global.crypto || require("crypto")
  global.fs = global.fs || require("fs")
  global.utils = global.utils || require("./utils")
  global.gameState = global.gameState || require("./game-state")
  Object.assign(exports, entities)
}
