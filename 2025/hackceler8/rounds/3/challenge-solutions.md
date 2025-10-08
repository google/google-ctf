# Forest temple

The inventory logic is changed so players can equip items even when dead.

When the goggles are equipped during the player death sequence they become alive and can move around again. Since there's no collision check during the death sequence (when the player falls up then down) this can be used to enter walls.

The miniboss is sealed off from the players but can be reached using the above glitch.

#  Fire temple

A check is removed from the map collision detection that makes the surrounded_by_tiles bit array stay filled if an entity goes OOB. In this case the game considers it to be surrounded by holes and makes it fall down.

The miniboss is given 31337 health which can't be reduced to 0 within the timespan of a round. However, it can be pushed around with each attack, so players can move it OOB and trigger the hole glitch to make it fall and die.

# Water temple

This challenge exploits the 128k boundary hardware bug described in https://plutiedev.com/dma-transfer#128kb-bug

The NPC guarding the door to the miniboss asks for a password that's stored at various fixed addresses in the ROM. It can also paint tiles from that fixed address space as long as it's not a password.

By asking it to paint an address at the correct 128k boundary, the hardware bug will cause the DMA to upload the secret tiles instead.

Solution: Ask for address 0x13ff00, which will cause the secret at 0x120100 to be rendered.

# Sky temple

A new behavior is introduced where players whose controller is disconnected from the console become inactive (disappear from the map).

There's a "cloak" item that a player can equip to hide from enemies.

To get to the miniboss, players have to press 4 switches, then walk through an area with invulnerable instakill enemies, then press another 4 switches. One player can get through the instakill area with the cloak on but the others can't.

Normally players can't be deactivated after they became active, but due to the new behavior we can get through the instakill area by disconnecting the controllers of P2-4 to deactivate them, then reconnect in the next map and have the 4 players press the second set of switches.

# Boss

The boss is invulnerable. There's a computer on the boss map that shows the minion kill history of each player and also allows players to change their names.

The player names are stored on a fixed-address buffer on the RAM. After that we store the offset at which the kills are logged (also fixed-address). The kills are logged as bits from a randomized offset (chosen once on every console reset when the boss areas is first entered).

There's no bounds check when players update their names so they can overflow into the area storing the kill buffer address. The next time they kill a minion, the bits will be set at an arbitrary address they specified.
However, the player doesn't know the random offset that's applied to the start address. To figure that out, the player can set the address to a fixed point, then read the kill history to see the bits at that location and figure out where in the ROM that is. Once they have this data they know the offset and can write arbitrary bits, allowing them to defeat the boss.

Example solution:
* Find the boss's "invulnerable" field on the stack:
  * Enter boss area in MAME debugger mode
  * `find 0,0xFFFFFF,w.0100,w.0000,w.0000,w.0000,w.0002`
  * Take third to last address, add 0x28
  * In hx8-handout.md this is ffce42
* Kill 32 minions (to be able to read 4 bytes)
* Set P4's name to PPPP PPPP PPPP PPPP AAAA AAAA (overflow + set the kill buf start address to 0)
* Read kills in the menu, note the bits (orc=0, angel=1)
* Find the 4 bytes read this way in the handout ROM. Example: We find the bytes at offset 0x758
* Subtract the offset from the address of the boss's "invulnerable" field on the stack: Example: 0xffce42 - 0x758 = 0xffc6ea
* Convert the address to the player name format. Example: 00ffc6ea -> AAPP MGOK
* Exit and reenter the map to reset the P1 kill count to 0
* Set P4 name to overflow again so that we can write the invulnerability: Example: PPPP PPPP PPPP PPPP AAPP MGOK
* Set the bool to false: Kill 8 Orcs
* The boss health bar should appear as the boss is no longer invulnerable. The player can now defeat it by punching it repeatedly.
