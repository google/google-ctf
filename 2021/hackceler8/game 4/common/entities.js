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
//   handleEvent(state, event):
//     Called if this object has subscribed to an event, and that event has fired.
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

entities.classes.Accumulator = class Accumulator {
  static init(state, data) {
    this.defaultCounter = data.properties.counter
    this.counter = this.defaultCounter
    this.logicOutput = 0
    this.pushed = false

    // Color stuff. Not actually animated.
    this.frameState = data.properties.frame_state
    entities.animResetFrameInfo(this, state)
  }

  static interact(state, input, types) {
    if ("down" in input) {
      if (this.pushed) {
        return
      }
      this.pushed = true
      this.counter -= 1
      if (this.counter == 0) {
        this.logicOutput = 1
        entities.updateLogic(this, state)
      } else if (this.counter < 0) {
        this.logicOutput = 0
        entities.updateLogic(this, state)
        this.counter = this.defaultCounter
      }
    } else {
      this.pushed = false
    }
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
    this.jumpProgress = -1        // Which state in the jump curve is the player in
    this.jumpV = 0                // Jump/fall velocity.
    this.moveV = 0                // Horizontal movement velocity.
    this.heldEntityId = null      // Item currently held in hand
    this.lastSolidGround = [this.x, this.y] // Last position where the player was standing on solid ground
    this.collidingEntities = {}   // Entities we are colliding with

    // Initialize animation properties:
    //   frameState:  Animation state.
    //   frame:  Animation frame.
    entities.animationEngines.Character.init.call(this, state, data)


    // Set up movement constants
    this.maxMovementSpeed = 240 * gameState.SEC_PER_TICK
    this.accelerationSpeed = 22 * gameState.SEC_PER_TICK
    this.stopSpeed = 27 * gameState.SEC_PER_TICK

    this.pushGravity = 1

    this.maxFallSpeed = 400 * gameState.SEC_PER_TICK

    this.jumpForceCurve = [
      160 * gameState.SEC_PER_TICK,
      80 * gameState.SEC_PER_TICK,
      55 * gameState.SEC_PER_TICK,
      55 * gameState.SEC_PER_TICK,
      50 * gameState.SEC_PER_TICK,
      50 * gameState.SEC_PER_TICK,
      45 * gameState.SEC_PER_TICK,
      45 * gameState.SEC_PER_TICK,
    ]
    this.DEATH_PENALTY = 10 // Seconds.
  }

  static death(state) {
    this.dead = true
    this.respawnTick =
        state.state.tick +
        gameState.TICKS_PER_SECOND * this.DEATH_PENALTY

    this.respawnPoint = this.lastSolidGround
    this.pickupLatch = false
  }

  static tick(state, input) {

    let gravity = 31.2 * gameState.SEC_PER_TICK

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

    if ("right" in input) {
      if (this.moveV < 0) {
        this.moveV = 0  // Reset to 0 if was going the other way.
      }

      this.moveV = Math.min(
          this.maxMovementSpeed, this.moveV + this.accelerationSpeed
      )
    } else if ("left" in input) {
      if (this.moveV > 0) {
        this.moveV = 0  // Reset to 0 if was going the other way.
      }

      this.moveV = Math.max(
          -this.maxMovementSpeed, this.moveV - this.accelerationSpeed
      )
    } else {
      if (this.moveV > 0) {
        this.moveV = Math.max(0, this.moveV - this.stopSpeed)
      } else {
        this.moveV = Math.min(0, this.moveV + this.stopSpeed)
      }
    }

    // Zero Gravity zones
    const zeroGravityZones = state.map.layers.metadata.getObjectsByType("zero_gravity")
    for (let i = 0; i < zeroGravityZones.length; i++) {
      const zeroGravityZone = zeroGravityZones[i]
      if (this.x >= zeroGravityZone.x && this.x < zeroGravityZone.x + zeroGravityZone.width &&
          this.y >= zeroGravityZone.y && this.y < zeroGravityZone.y + zeroGravityZone.height) {
        gravity = 0.0
        break
      }
    }

    // Negative gravity zones
    const negativeGravityZones = state.map.layers.metadata.getObjectsByType("negative_gravity")
    for (let i = 0; i < negativeGravityZones.length; i++) {
      const zeroGravityZone = negativeGravityZones[i]
      if (this.x >= zeroGravityZone.x && this.x < zeroGravityZone.x + zeroGravityZone.width &&
        this.y >= zeroGravityZone.y && this.y < zeroGravityZone.y + zeroGravityZone.height) {
        gravity = -31.2 * gameState.SEC_PER_TICK
        break
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
      this.jumpV = this.pushGravity  // Push player into the ground.
      if (("up" in input) && (this.jumpProgress == -1)) {
        this.jumpProgress = 0  // Start the jump;
      }

    } else {
      this.jumpV = Math.min(this.maxFallSpeed, this.jumpV + gravity)
    }

    if ("up" in input) {
      if (this.jumpProgress != -1 && this.jumpProgress < this.jumpForceCurve.length) {
        var oldUp = this.jumpV
        this.jumpV -= this.jumpForceCurve[this.jumpProgress] + gravity
        this.jumpProgress++;
      }
    } else {
      this.jumpProgress = -1
    }

    // Tick the animation engine to potentially update the frame.
    entities.animationEngines.Character.tick.call(this, state)

    if (this.frameSet === undefined) {
      throw "Animated object doesn't have a frameSet. Did you remember to set the is_frameset property on the tileset?"
    }

    const currentFrame = state.map.framesets[this.frameSet].getFrame(
        this.frameState, this.frame
    )

    // For "efficiency", don't recalculate collisions/position if we haven't moved.
    if (this.moveV != 0 || this.jumpV != this.pushGravity || !this.solidGround) {
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
      this.collidingEntities = collidingEntities

      // In case it wasn't possible to move vertically the whole way, cut the
      // jump velocity.
      // TODO: Just return the case from calculatePotentialMove instead of this
      // check.
      if (this.y !== currentY + this.jumpV && this.jumpV < 0) {
        this.jumpV = 0
      }
    }

    // Death awaits below the map.
    if (this.y > state.map.canvasH) {
      Player.death.call(this, state)
    }

		if ("k" in input) {
      Player.death.call(this, state)
		}

    // Death awaits in death zones.
    const deathZones = state.map.layers.metadata.getObjectsByType("death")
    for (let i = 0; i < deathZones.length; i++) {
      const deathZone = deathZones[i]
      if (this.x >= deathZone.x && this.x < deathZone.x + deathZone.width &&
          this.y >= deathZone.y && this.y < deathZone.y + deathZone.height) {
        Player.death.call(this, state)
      }
    }

    if (this.solidGround && !this.dead) {
      this.lastSolidGround = [this.x, this.y]
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
    Object.entries(this.collidingEntities).forEach(e => {
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
      Object.entries(this.collidingEntities).forEach(e => {
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
        entity.x = this.x + 16
        if (entity.pickupHeight) {
          entity.y = this.y - entity.pickupHeight
        } else {
          entity.y = this.y
        }
      }
    }
  }
}

// Lerp from one position to another. Works on single values, points, etc.
entities.Lerp = class Lerp {
  static init(from, to, time) {
    this.from = from
    this.to = to
    this.time = time * 1000
    this.accumTime = 0
  }
  static tick() {
    this.accumTime += gameState.MS_PER_TICK
    const fracDone = this.accumTime / this.time

    if (fracDone >= 1) {
      return {"val": this.to, "done": 1}
    }

    var ret = this.from.map((val, idx) => {
      const from = val
      const to = this.to[idx]
      const new_val = from + ((to - from) * fracDone)
      return new_val
    })

    return {"val": ret, "done": 0}
  }
  static setTime(t) {
    this.accumTime = t * 1000
  }
  static overTime() {
    return (this.accumTime - this.time) / 1000.0
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

    this.frameState = "flag_" + this.challengeID.substr(-1)
    entities.animResetFrameInfo(this, state)
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

    const challengeState = state.state.meta.challenges[this.challengeID]

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

    this.frameState = "flag_" + this.challengeID.substr(-1)
    entities.animResetFrameInfo(this, state)
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

entities.animationEngines.Savepoint = class Savepoint {
  static init(state) {
    this.frameState = "closed"
    entities.animResetFrameInfo(this, state)
  }

  static tick(state, animProps) {
    const animationOver = entities.animTickFrame(this, state)
    let frameStateChanged = false

    const setFrameState = (newState) => {
        this.frameState = newState
        frameStateChanged = true
    }

    if (this.near) {
      // The player is close to the savepoint.
      if (this.frameState === "closed" || this.frameState === "closing") {
        setFrameState("opening")
      } else if (this.frameState === "opening" && animationOver) {
        setFrameState("open")
      }
    } else {
      if (this.frameState === "open" || this.frameState === "opening") {
        setFrameState("closing")
      } else if (this.frameState === "closing" && animationOver) {
        setFrameState("closed")
      }
    }

    if (frameStateChanged) {
      entities.animResetFrameInfo(this, state)
    }
  }
}

entities.classes.Savepoint = class Savepoint {
  static init(state, data) {
    this.interacting = false
    this.showing = false
    this.saveLatch = false
    this.near = false
    entities.animationEngines.Savepoint.init.call(this, state)
  }

  static tick(state, input) {
    const player = state.state.entities.player
    this.near = Math.sqrt(((this.x - player.x) ** 2 + (this.y - player.y) ** 2)) < 200
    entities.animationEngines.Savepoint.tick.call(this, state)
    if (this.showing && !this.interacting) {
      this.showing = false

      if (!state.backendObjects) {
        // Browser.
        const saverUI = globals.game.getGameSaverUIObject()
        saverUI.hide()
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
        const saverUI = globals.game.getGameSaverUIObject()
        saverUI.hide()
      }
    }

    if (!this.showing && "down" in input) {
      this.showing = true

      if (!state.backendObjects) {
        // Browser.
        const saverUI = globals.game.getGameSaverUIObject()
        saverUI.setStatus("start")
        saverUI.show()
      }
    }

    if ("save" in input && this.showing && this.saveLatch == false) {
       // Changes here are irreversible.
      const save = input.save

      if (state.backendObjects) {
        // Backend.

        state.backendObjects.playersDB.saveSavegame(state.backendObjects.username, input.save, state.state)
        console.log("Saved game", save)
      } else {
        // Browser.
        const saverUI = globals.game.getGameSaverUIObject()
        saverUI.setStatus("saved")
      }
      this.saveLatch = true
    } else {
      this.saveLatch = false
    }
  }
}

entities.classes.Control = class Control {
  static init(state, data) {
    if (data.properties.spawn) {
      this.spawn = data.properties.spawn
    } else {
      this.spawn = null
    }

    if (data.properties.pulseDuration) {
      this.pulseDuration = data.properties.pulseDuration
    } else {
      this.pulseDuration = 5
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

      this.logicOutput = 1
      entities.updateLogic(this, state)

      // Code for spawning specified item
      if (this.spawn) {
        var new_entity = state.duplicateEntity(this.spawn)
        if (new_entity !== null) {
          var offsetX = utils.deterministicRandom(state.state.randState)
          var offsetY = utils.deterministicRandom(state.state.randState)
          new_entity.x = this.x + 48 + (offsetX % 16)
          new_entity.y = this.y + 24 + (offsetY % 16)
          state.addEntity(new_entity)
        }
      }

      // Animation stuff
      this.tickdown = this.pulseDuration
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

        this.logicOutput = 0
        entities.updateLogic(this, state)

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

entities.classes.Toggle = class Toggle {
  static init(state, data) {
    this.collision = false
    this.frameState = "default"
    this.wasHigh = 0

    entities.animationEngines.Simple.init.call(this, state, data)

    if (data.properties.frame_state !== undefined) {
      this.frameState = data.properties.frame_state
    }

    this.logicOutput = parseInt(this.frameState.substr(-1))

    entities.subscribeLogic(this, state, data.properties.input)
    entities.animResetFrameInfo(this, state)
  }

  static handleEvent(state, event) {
    if (event.type == "logic") {
      entities.classes.Toggle.handleLogic.call(this, state, event.sender, event.value)
      return
    }
  }

  static handleLogic(state, sender, value) {
    if (value) {
      if (this.wasHigh) {
        return
      }
      this.wasHigh = true
      if (this.frameState == "toggle_0") {
        this.frameState = "toggle_1"
        this.logicOutput = 1
      } else {
        this.frameState = "toggle_0"
        this.logicOutput = 0
      }
      entities.updateLogic(this, state)
    } else {
      this.wasHigh = false
    }
    entities.animResetFrameInfo(this, state)
  }
}

entities.classes.Rng = class Rng {
  static init(state, data) {
    this.collision = false
    this.frameState = "rng_0"

    if (data.properties.frame_state !== undefined) {
      this.frameState = data.properties.frame_state
    }
    if (data.properties.random_duration !== undefined) {
      this.randomDuration = data.properties.random_duration
    } else {
      this.randomDuration = 1.0
    }

    this.toggle = (data.properties.toggle === true)

    this.logicOutput = parseInt(this.frameState.substr(-1))

    entities.subscribeLogic(this, state, data.properties.input)
    entities.animResetFrameInfo(this, state)
  }

  static handleEvent(state, event) {
    if (event.type == "logic") {
      entities.classes.Rng.handleLogic.call(this, state, event.sender, event.value)
      return
    }
  }

  static handleLogic(state, sender, value) {
    if (!value) {
      if (this.toggle) {
        // we're in toggle mode - don't change output on low edge
        return
      } else {
        // not in toggle mode - set output to 0 on low edge
        this.logicOutput = 0
        entities.updateLogic(this, state)
        return
      }
    }

    // value is true, clear and start the random animation
    this.logicOutput = 0
    entities.updateLogic(this, state)
    this.frameState = "rng_randomization_0"
    entities.animResetFrameInfo(this, state)

    this.remainingDuration = this.randomDuration
  }

  static tick(state) {
    if (this.remainingDuration === undefined) {
      return
    }
    if (this.remainingDuration <= 0) {
      delete this.remainingDuration

      const randval = utils.deterministicRandom(state.state.randState) % 2
      this.logicOutput = randval
      entities.updateLogic(this, state)

      this.frameState = "rng_" + randval.toString()
      entities.animResetFrameInfo(this, state)
    } else {
      this.remainingDuration = this.remainingDuration - gameState.MS_PER_TICK / 1000
      entities.animationEngines.Simple.tick.call(this, state)
    }
  }
}

entities.classes.And = class And {
  static init(state, data) {
    this.collision = false
    this.frameState = "default"
    this.inputs = data.properties.input.split("\n")

    entities.animationEngines.Simple.init.call(this, state, data)

    if (data.properties.frame_state !== undefined) {
      this.frameState = data.properties.frame_state
    } else {
      console.error("No data.properties.frame_state on And.")
    }

    this.logicOutput = parseInt(this.frameState.substr(-1))

    this.inputs.map(input => {
      entities.subscribeLogic(this, state, input)
    })

    entities.animResetFrameInfo(this, state)
  }

  static handleEvent(state, event) {
    if (event.type == "logic") {
      entities.classes.And.handleLogic.call(this, state, event.sender, event.value)
      return
    }
  }

  static handleLogic(state, sender, value) {
    var newOutput = 1;
    this.inputs.map(input => {
      const newValue = state.state.entities[input].logicOutput;

      if (newValue == 0) {
        newOutput = 0;
      }
    })

    const left = state.state.entities[this.inputs[0]].logicOutput;
    const right = state.state.entities[this.inputs[1]].logicOutput;

    this.frameState = this.frameState.slice(0, -4) + left.toString() + right.toString() + "_" + newOutput.toString()

    if (newOutput != this.logicOutput) {
      this.logicOutput = newOutput
      entities.updateLogic(this, state)
    }

    entities.animResetFrameInfo(this, state)
  }
}

entities.classes.Inverter = class Inverter {
  static init(state, data) {
    this.collision = false
    this.frameState = "default"

    entities.animationEngines.Simple.init.call(this, state, data)

    if (data.properties.frame_state !== undefined) {
      this.frameState = data.properties.frame_state
    } else {
      console.error("No data.properties.frame_state on Inverter.")
    }

    this.logicOutput = parseInt(this.frameState.substr(-1))

    entities.subscribeLogic(this, state, data.properties.input)
    entities.animResetFrameInfo(this, state)
  }

  static handleEvent(state, event) {
    if (event.type == "logic") {
      entities.classes.Inverter.handleLogic.call(this, state, event.sender, event.value)
      return
    }
  }

  static handleLogic(state, sender, value) {
    if (value) {
      this.logicOutput = 0
      this.frameState = this.frameState.slice(0, -1) + "0"
    } else {
      this.logicOutput = 1
      this.frameState = this.frameState.slice(0, -1) + "1"
    }
    entities.updateLogic(this, state)
    entities.animResetFrameInfo(this, state)
  }
}

// Adds 'duration' to each pulse.
entities.classes.Extender = class Extender {
  static init(state, data) {
    this.collision = false
    this.frameState = "default"
    this.duration = data.properties.duration

    entities.animationEngines.Simple.init.call(this, state, data)

    if (data.properties.frame_state !== undefined) {
      this.frameState = data.properties.frame_state
    } else {
      console.error("No data.properties.frame_state on Extender.")
    }

    this.logicOutput = 0

    entities.subscribeLogic(this, state, data.properties.input)
    entities.animResetFrameInfo(this, state)
    this.frame = this.animFrameCount - 1
  }

  static handleEvent(state, event) {
    if (event.type == "logic") {
      entities.classes.Extender.handleLogic.call(this, state, event.sender, event.value)
      return
    }
  }

  static handleLogic(state, sender, value) {
    if (value) {
      this.timeSpent = 0
      entities.animResetFrameInfo(this, state)
      if (!this.logicOutput) {
        this.logicOutput = 1
        entities.updateLogic(this, state)
      }
    }
  }

  static tick(state) {
    if (this.timeSpent === undefined) {
      return
    }
    /*
  anim.frame = (anim.frame + 1) % anim.animFrameCount
  const endOfFrames = (anim.frame === 0)
  return endOfFrames
  */

    const fracDone = this.timeSpent / this.duration
    const targetFrame = Math.floor(fracDone * (this.animFrameCount - 1))
    this.frame = targetFrame

    if (this.timeSpent >= this.duration) {
      this.logicOutput = 0
      entities.updateLogic(this, state)
      delete this.timeSpent
      return
    }

    this.timeSpent += gameState.MS_PER_TICK / 1000

  }
}

entities.classes.Wire = class Wire {
  static init(state, data) {
    this.collision = false
    this.frameState = "default"

    entities.animationEngines.Simple.init.call(this, state, data)

    if (data.properties.frame_state !== undefined) {
      this.frameState = data.properties.frame_state
    } else {
      console.error("No data.properties.frame_state on Wire.")
    }

    entities.subscribeLogic(this, state, data.properties.input)
    entities.animResetFrameInfo(this, state)
  }

  static handleEvent(state, event) {
    if (event.type == "logic") {
      entities.classes.Wire.handleLogic.call(this, state, event.sender, event.value)
      return
    }
  }

  static handleLogic(state, sender, value) {
    if (value) {
      this.frameState = this.frameState.slice(0, -1) + "1"
    } else {
      this.frameState = this.frameState.slice(0, -1) + "0"
    }
    entities.updateLogic(this, state)
    entities.animResetFrameInfo(this, state)
  }
}



entities.classes.KeyReceptacle = class KeyReceptacle {
  static init(state, data) {
    if (this.collision === undefined) {
      this.collision = true
    }
    if (data.properties.invert === true) {
      this.invert = 1
    } else {
      this.invert = 0
    }
    this.logicOutput = this.invert

    this.holds_key = false
    this.tickdown = null
    var prefix = "locked_"

    if (data.properties.holds_key) {
      this.holds_key = data.properties.holds_key
      if (this.holds_key) {
        this.logicOutput = 1 - this.invert
        prefix = "unlocked_"
        this.tickdown = 0
      } else {
        this.logicOutput = this.invert
      }
    }


    if (data.properties.value !== undefined) {
      this.value = data.properties.value
      this.frameState = prefix + this.value
    } else {
      this.frameState = prefix + "0"
      console.warn("KeyReceptacle is missing value property.")
      this.value = null
    }
    entities.animResetFrameInfo(this, state)
  }

  static tick(state) {
    const did_hold_key = this.holds_key
    this.holds_key = false

    const player = state.state.entities.player
    for (const id in state.state.entities) {
      if (id == this.id) { continue }

      const key = state.state.entities[id]
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
          this.logicOutput = this.invert
          entities.updateLogic(this, state)
        }
      }
      entities.animResetFrameInfo(this, state)
    }

    if (this.holds_key && this.tickdown) {
      this.tickdown = this.tickdown - 1
      if (this.tickdown == 0) {
        // Once the key has been in the receptacle long enough for the animation
        // to play, open attached doors.
          this.logicOutput = 1 - this.invert
          entities.updateLogic(this, state)
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

entities.classes.Door = class Door {
  static init(state, data) {
    this.frameState = "default"
    if (data.properties.value !== undefined) {
      this.value = data.properties.value
    } else {
      console.log("door", this.id, "does not have value")
      this.value = 0
    }
    var open = "closed"
    if (data.properties.open === true) {
      open = "open"
    }
    this.frameState = open + this.value.toString()

    this.collision = true
    if (data.properties.invert === true) {
      this.invert = true
    } else {
      this.invert = false
    }

    if (data.properties.input !== undefined) {
      entities.subscribeLogic(this, state, data.properties.input)
    } else {
      console.warning("Door", this.id, "does not have its input set.")
    }

    entities.animResetFrameInfo(this, state)
  }

  static interact(state, input, types) {
  }

  static handleEvent(state, event) {
    if (event.type == "logic") {
      entities.classes.Door.handleLogic.call(this, state, event.sender, event.value)
      return
    }
  }

  static handleLogic(state, sender, value) {
    if (this.invert) {
      value = !value
    }
    if (value) {
      this.frameState = "open" + this.value.toString()
    } else {
      this.frameState = "closed" + this.value.toString()
    }
    entities.animResetFrameInfo(this, state)
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
    if (this.open && !this.frameState.includes("open")) {
      this.frameState = "opening"
      entities.animResetFrameInfo(this, state)
    }

    const endOfFrames = entities.animTickFrame(this, state)
    if (endOfFrames && this.frameState.includes("opening")) {
      this.frameState = "open"
      entities.animResetFrameInfo(this, state)
      entities.animTickFrame(this, state)
    }

    if (this.noCarry) {
      const player = state.state.entities.player
      if (player.heldEntityId !== null && !this.frameState.includes("_blocked")) {
        this.frameState = this.frameState + "_blocked"
      } else if (player.heldEntityId === null && this.frameState.includes("_blocked")) {
        this.frameState = this.frameState.replace("_blocked", "")
      }
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
    this.noCarry = data.properties.no_carry === true

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
      const challenges = state.state.meta.challenges
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
      const player = state.state.entities.player
      if (this.noCarry && player.heldEntityId !== null) {
        console.log("No.")
        return
      }
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
    entities.animationEngines.Simple.init.call(this, state, data)

    this.collision = true
    this.requiredOrbs =
        data.properties.required_orbs.split("\n")
        .map(e => e.trim())
        .filter(e => e.length)
  }

  static tick(state) {
    if (!this.open) {
      const challenges = state.state.meta.challenges
      if (this.requiredOrbs.every(e => challenges[e].solved)) {
        this.frameState = "open"
        entities.animResetFrameInfo(this, state)
        this.open = true
      }
    }
  }
}

entities.classes.Escape = class Escape {
  static interact(state, input, types) {
    if (!state.state.victory) {
      const challenges = Object.entries(state.state.meta.challenges)
      if (!challenges.every(e => e[1].solved)) {

        if (!state.backendObjects && state.state.tick % 60 == 0) {
          console.log("Go solve challenges.")
        }

        return
      }

      state.state.victory = true

      const now = ((+new Date()) / 1000) | 0
      console.warn(`----- ESCAPE ${this.challengeID} at ${now}`)

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

entities.classes.Exploder = class Exploder {
  static init(state, data) {
    this.pickupAble = true
    this.pickupHeight = 4
    this.frameState = "default"
    entities.animationEngines.Simple.init.call(this, state, data)
  }

  static interact(state, input, types) {
    if ("down" in input) {
      // Cannot explode more than 1 Exploder at a time.
      for (const id in state.state.entities) {
        const other_entity = state.state.entities[id]
        if (other_entity.type === "ExplodingExploder" && id != "exploding_exploder_template") {
          return
        }
      }
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

      const player = state.state.entities.player

      // Apply a velocity to the player due to the explosion.
      const playerPos = [player.x + 94/2, player.y + 60/2]
      const ourPos = [this.x + 16/2, this.y + 16/2]
      var forceVector = [playerPos[0] - ourPos[0], playerPos[1] - ourPos[1]]
      const magnitude = Math.sqrt(forceVector[0] * forceVector[0] + forceVector[1] * forceVector[1])
      // Normalize the vector
      forceVector = [forceVector[0] / magnitude, forceVector[1] / magnitude]
      // Divide by magnitude again, because we want ^2 dropoff
      //forceVector = [forceVector[0] / magnitude, forceVector[1] / magnitude]
      // Scale by force
      const explosionForce = 10
      forceVector = [forceVector[0] * explosionForce, forceVector[1] * explosionForce]
      // Apply velocity to the player
      player.moveV += forceVector[0]
      player.jumpV += forceVector[1]
      player.canJump = false
      player.solidGround = false

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

entities.classes.FloatingPlatform = class FloatingPlatform {
  static init(state, data) {
    this.collision = true
    this.frameState = "default"
    this.startTick = state.state.tick
    entities.animationEngines.Simple.init.call(this, state, data)

    if (data.properties.frame_state !== undefined) {
      this.frameState = data.properties.frame_state
      entities.animResetFrameInfo(this, state)
    } else {
      this.frameState = "default"
      entities.animResetFrameInfo(this, state)
    }

    this.startingPos = [this.x, this.y]

    var path_parse = data.properties.path
    path_parse = path_parse.split(/\n/)
    this.path = path_parse.map((point) => {
      var xys = point.split(/,/)
      return [parseInt(xys[0]) + this.x, parseInt(xys[1]) + this.y, parseFloat(xys[2])]
    })
    this.targetIdx = 0
    this.lerp = {}
    entities.Lerp.init.call(this.lerp, [this.x, this.y], this.path[this.targetIdx].slice(0, 2), this.path[this.targetIdx][2])
    if (data.properties.starting_offset) {
      entities.Lerp.setTime.call(this.lerp, data.properties.starting_offset)
    }
  }

  static tick(state) {
    entities.animationEngines.Simple.tick.call(this, state)
    const lerpresult = entities.Lerp.tick.call(this.lerp)
    this.x = lerpresult.val[0]
    this.y = lerpresult.val[1]

    if (lerpresult.done) {
      this.targetIdx += 1
      if (this.targetIdx >= this.path.length) {
        this.targetIdx = 0
        this.x = this.startingPos[0]
        this.y = this.startingPos[1]
      }
      const overTime = entities.Lerp.overTime.call(this.lerp)
      this.lerp = {}
      entities.Lerp.init.call(this.lerp, [this.x, this.y], this.path[this.targetIdx].slice(0, 2), this.path[this.targetIdx][2])
      entities.Lerp.setTime.call(this.lerp, overTime)
    }
  }
}

// Subscribe to logic-gate updates from the specified entity.
// Subscribing entities will have handleLogic()
entities.subscribeLogic = (subscribingEntity, state, inputEntityId) => {
  entities.eventQueue.subscribe(state, subscribingEntity, "logic", inputEntityId)
}

// Publish a logic-gate update to subscribers.
entities.updateLogic = (sendingEntity, state) => {
  entities.eventQueue.sendEvent({
    "sender": sendingEntity.id,
    "type": "logic",
    "value": sendingEntity.logicOutput,
  })
}

// Support for sending events between entities. Events are delivered the next frame, prior to entity tick()s.
// Events have at least the following properties:
//   sender: the ID of the entity sending the event.
//   type: a string identifying the event type. Defaults to empty string.
// Events can have any additional properties.
//
// Entities can "subscribe" to events by type and optionally sender.
// Entities subscribing to events must implement the .handleEvent(state, event) function.

class EventQueue {
  constructor() {
    this.events = []
  }

  sendEvent(event) {
    if (event.type === undefined) {
      event.type = ""
    }
    this.events.push(event)
  }

  subscribe(state, entity, type, sender=undefined) {
    if (state.state.subscribers === undefined) {
      state.state.subscribers = {}  // {types: {"global": [entityIds], "by_sender": {sender_names: [entityIds]}}}
    }

    if (sender !== undefined && sender.hasOwnProperty("id")) {
      sender = sender.id
    }

    if (state.state.subscribers[type] === undefined) {
      state.state.subscribers[type] = {"global": [], "by_sender": {}}
    }
    if (sender === undefined) {
      state.state.subscribers[type].global.push(entity.id)
    } else {
      if (state.state.subscribers[type].by_sender[sender] === undefined) {
        state.state.subscribers[type].by_sender[sender] = []
      }
      state.state.subscribers[type].by_sender[sender].push(entity.id)
    }
  }

  tick(state) {
    const events = this.events
    this.events = []
    events.map(event => {
      this._triggerEvent(state, event)
    })
  }

  // private.
  _triggerEvent(state, event) {
    if (state.state.subscribers === undefined) {
      return
    }

    const subscribers = state.state.subscribers[event.type]
    if (subscribers === undefined) {
      return
    }
    subscribers.global.map(entityId => {this._sendEventToEntity(state, event, entityId)})

    const by_sender = subscribers.by_sender[event.sender]
    if (by_sender !== undefined) {
      by_sender.map(entityId => {this._sendEventToEntity(state, event, entityId)})
    }
  }

  // private.
  _sendEventToEntity(state, event, entityId) {
    const entity = state.state.entities[entityId]
    if (entity === undefined) {
      return
    }
    const entityClass = entities.classes[entity.type]
    if (entityClass === undefined) {
      return
    }
    if (entityClass.handleEvent === undefined) {
      return
    }

    entityClass.handleEvent.call(entity, state, event)
  }
}

entities.eventQueue = new EventQueue()

// Node.js compliance.
if (typeof window === 'undefined') {
  global.crypto = global.crypto || require("crypto")
  global.fs = global.fs || require("fs")
  global.utils = global.utils || require("./utils")
  global.gameState = global.gameState || require("./game-state")
  Object.assign(exports, entities)
}
