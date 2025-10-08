# Forest temple

The item collection logic is changed so that items would be collected multiple times if multiple players collide with them at the same time.

The entrance leading to the miniboss is closed with 3 doors but there is only 1 key on the map. Players need to exploit the multi-collection glitch to get the item.
One easy way to collide with the item at the same frame:
* Stand next to the item with one player
* Join with 2 other players
* Press pause
* Hold the walk button towards the item with all players
* Unpause game

# Fire temple

An NPC gives the player a key but only once. However, there are 4 doors that need to be opened to get to the boss.

The way the NPC checks for the key already being handed out is by looking for a key in the player's inventory. The player can thus use the key to open one door (removing it from the inventory), then go back to the NPC to pick up another one.

# Water temple

When a player switches maps while another player's death sequence is played, the player "resurrects" with 0 health. They can then no longer be killed with regular enemies and can walk to the miniboss unscathed.

# Sky temple

5 out of the 12 chests contain a key and 7 are mimics. Their positions are randomized after every entry, with a PRNG seed that's the same on every game restart.

Players don't know the seed on the live console and if they approach the chests again after a game over they'll be shuffled again. However, if they hard reset the game (press the reset button on the console), the positions will be the same as in the previous run.

Players can thus figure out the real chest positions by entering the map, opening chests until all players die, noting the key positions they found, resetting the console and trying again until they went through all 12 chests.

Since only one of the players die if they open a mimic teams can figure out the key positions from at most 3 save scumming attempts (4 deaths per try).

# Boss

The boss cannot be defeated normally. However, one can have a dialogue with the boss where the following happens:
* A NOP sled shellcode is sent to the VRAM
* The player is allowed to send data to any number of VDP_CONTROL and VDP_DATA registers
* The shellcode is loaded from the VRAM back into the RAM and executed.

If the player figures out how to set the VDP registers correctly, they can trigger a DMA and upload their own shellcode which causes the boss to be defeated.

One solution:
* Run the game in MAME debugger mode
* Enter the boss area
* Find the address of enemy.status for the boss: `find 0,0xFFFFFF,w.0100,w.0000,w.0000,w.0000,w.0002`
* Take the last addr found -> 0xffcd06 in hx8-handout.md
* Shellcode to set status to "dying":
```
267c 00ff cd22   movea.l #$ffcd06, A3
177c 0004 0000   move.b  #$4, ($0,A3)
```
* Enter above shellcode using DMA:
  * Set 9 registers
  * Control, 0x8f02
  * Control, 0x4000
  * Control, 0x3
  * Data, 0x267c
  * Data, 0xff
  * Data, 0xcd06
  * Data, 0x177c
  * Data, 0x4
  * Data, 0x0
