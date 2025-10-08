# Forest temple

The racoon NPC image includes additional data that's loaded onto the VRAM but never rendered. If the player can guess what text is in those tiles they get a key to unlock the miniboss area.

The text on the image is different for the live console and the offline round handout, so players will have to leak it live.

A bug is introduced where remaining inactive players can be activated after all other players have died and the GameOver screen has appeared. This causes an "use-after-free": The GameOver text stays on screen but the tile addresses it uses can be overwritten by new tiles being loaded, resulting in a garbled game over screen with random tiles when the player moves to a new map.

If the player moves to the map of the NPC, the secret text will be visible among the tiles on the garbled gameover screen.

The changes for this challenge also introduced an unintended teleportation bug: Players can now spawn to the last alive position of P1 (from whichever map P1 was last alive on), allowing them to teleport to most places if they set up P1's position the right way. This can be (and has been) used to circumvent all challenges of this round except for the boss battle.

#  Fire temple

The player needs to get keys from mimics with the same setup as in the VRAM overflow challenge. Here, mimics use a world-specific palette. Additionally, the mimics and real chests have the same colors on the correct world's palette, but different ones on other worlds' palettes.

A bug is introduced in which, when moving between worlds, the UI background darkener updates its world_type a tick too late. If the player opens the inventory on the same tick as when the world is loaded, they trigger the UI's screen darkening logic with the previous world's palette, resulting in the palette being switched out to a different world's, where mimic graphics are different. The player can use this to see which chests are mimics.

Since the world switch fading takes over execution until fading finishes, controller states aren't updated during this time. If the player starts holding the start button during the fading sequence, the game will register it as "just pressed" on the first frame of the new world, thus players doesn't actually need to do any frame perfect timing.

# Water temple

On the path leading to the miniboss the player needs to walk through 4 rows where only 1 out of the 7 rectangles is safe. If the player steps on the wrong one they die.

The safe rectangles are chosen with a PRNG that gets seeded with ctx.frame when the player enters the map. With random tries the player only has a 1 in 7^4 (2401) chance of succeeding.

The player can reset the console and use a series of controller button presses to enter the water temple at the exact same frame every time. This allows them to know in advance where the unsafe tiles are and navigate around them.

# Sky temple

This is a reversing challenge where players need to figure out the correct input for the NPC's password checking logic.

The password is converted to a pixel bitfield and rendered on the screen (covered by the dialogue box so players don't see it) through a number of sprites of various sizes and positions.

A "mask" tileset is also loaded onto the screen with similar sprites. To get the correct password, the mask image needs to perfectly fit into the password image. This is checked with the status register's SC bit that tells us if any sprite pixels have collided.

# Boss

3 new features are added:
* A "cloak" item - Players wearing the cloak are invisible to enemies
* Friendly fire between players - players can hit and thus push each other
* An NPC that warps you back to the main map with all your items

The boss makes "snapshots" of the player's last 4 position (pushes them as bytes into a buffer) then "rewinds" time, moving players back through the 4 positions to their starting positions and emptying the buffer.

This buffer also has some dummy code (a NOP sled) at the end which gets executed when players press a switch.

Player 4 can overflow the buffer and overwrite the NOP sled with arbitrary code as follows:
* Whenever the boss stores a new position, have the cloak unequipped.
* Whenever the boss rewinds time, have the cloak equipped. This makes the boss skip P4 and not pop any of its pushed positions.

With manual play it's difficult to stand at precise positions to control the bytes for the shellcode, but players can hug walls and corners to take on the specific positions needed for a simple shellcode.

Players can also hit each other to move themselves by a constant offset.

One possible solution that can be entered by hugging the right corner / getting hit in the right direction:

```
# Load boss ptr from const address
267c 00ff ffb4      movea.l #$ffffb4, A3
266b 0000           movea.l ($0,A3), A3
# Set boss state to "dying"
177c 0004 008E      move.b  #$4, ($0x8E,A3)
```

See pos-rce-solution.png for a possible wall hugging / friendly fire sequence that inputs this shellcode.
