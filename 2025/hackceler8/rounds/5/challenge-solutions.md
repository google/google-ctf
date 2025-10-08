# Forest temple

A new InvisibleKey item is introduced that behaves just like the regular key but doesn't have any visible sprite. It's also not present on any map file but rather added onto the water level dynamically.

Other keys from the level have been removed so players need to find the invisible keys to be able to get to the miniboss.

Additionally, the invisible keys use the same item ID as a Googles and Boots item that's conveniently placed in the player's path. If the player picks up those items, the invisible key IDs will register as "collected" and won't show up when the right map is entered.

Key locations:
* e22.tmx, next to Boots
* e20.tmx, below the right Heart

#  Fire temple

The map with the miniboss has instakill blobs that the player needs to walk between without touching them. This is difficult to do manually at full speed but relatively simple if the game is ~10x slower.
The previous map has switches that spawn flame enemies next to P1. The switches can be pressed multiple times to spawn enemies until the vector is full.

If P1 stands next to the entrance to the miniboss map when the flame enemies spawn, they will walk off screen. After they walk off screen and the player walks into the miniboss map, they will be on screen again after the map scroll (and thus not despawn). The flame enemies will cause the game to lag, making it possible to manually walk between the instakill blobs without dying.

# Water temple

The water map is replaced with a maze during build, with only the generated Rust files of the maps being available (no .tmx files). Players need to piece together the map and run a maze solver on it or mod their client to find the quickest path.

# Sky temple

The console saves players' inventory between console resets.

There are 2 doors on the map that need to be opened but only 1 key.

Players can open both doors by  getting the key, resetting the console, then getting it again.

# Boss

The boss is invulnerable. They also allow the player to write bytes into a buffer with a player-specified offset. There's a length check to make sure the buffer doesn't overflow.

The length check is done assuming the offset is in bytes but it's actually in u32 ptr size, so it offsets 4x as many bytes as the check expects. This allows the player to write into the stack far enough to rewrite the return address and perform ROP but not too far that they could just directly set the boss to "dead" further down the stack.

One potential ROP to defeat the boss: Return into enemy::kill with the &self param being the boss's address on the stack. Then return into the regular program execution.

Here's how to find various necessary addresses using MAME and their value in hx8-handout.md:
* The normal return address when this function is called:
  * `wp 123456,2,r` (The code conveniently reads from 0x123456 in the dialogue function)
  * Go through a regular dialogue in-game
  * Upon breaking press "Step Out"
  * Note PC value -> 0x162b6
* The buffer's distance from the stored return address on thestack: Set a breakpoint to the return instruction
  * Follow above flow again, setting the buffer to something recognizable like FFFFFFFF....
  * After "Step Out", run `history`, set breakpoint to return address
  * Run through dialogue again, upon reaching the breakpoint inspect the memory, looking for the start of the buffer and its distance from the return address (current SP value)
  * -> 1028 bytes -> 257 u32
* enemy::kill address and address of the boss on the stack: Printed by the game when an enemy falls down a hole
  * -> f2a4, ffce1c

Combining all of these, the payload for the ROP is
* Offset: 257
* Contents: `00 00 f2 a4 00 01 62 b6 00 ff ce 1c`
