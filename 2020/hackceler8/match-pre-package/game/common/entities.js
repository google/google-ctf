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
  }
}

entities.animResetFrameInfo = function(anim, state) {
  //console.log(state.map.framesets)
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

    entities.animationEngines.Simple.init.call(this, state, data)
  }

  static tick(state) {
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
    if (this.open && this.frameState != "open") {
      this.frameState = "open"
      entities.animResetFrameInfo(this, state)
    }

    entities.animTickFrame(this, state)
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

entities.classes.Escape = class Escape {
  static interact(state, input, types) {
    state.state.victory = true
  }
}

// Node.js compliance.
if (typeof window === 'undefined') {
  global.crypto = global.crypto || require("crypto")
  global.utils = global.utils || require("./utils")
  global.gameState = global.gameState || require("./game-state")
  Object.assign(exports, entities)
}
