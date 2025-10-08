# Forest temple

Two bugs are introduced:
* An NPC equips a random item to the player, but doesn't check if it was already equipped to someone else.
* The map scrolling starts when the player is in a 4px wide band off-screen instead of being anywhere off-screen.

Normally the map scrolling would always trigger even if the player runs a bit faster. It's possible to avoid it by increasing the speed a lot through the following glitch:
* Have P2 equip boots
* Have P1 talk to the NPC and equip boots. The effects of boots is still active on P2
* Have P1 unequip boots and have P2 equip it. The boots effect is now applied to P2 twice.
* Repeat until P2 has a speed of 10 (10 px every frame).

Now when P2 walks out the map they won't trigger the scroll and instead can walk around the border. They can use this to walk downward for about a minute until their 16-bit position variable overwraps and they come through the other side of the map.

The path to the miniboss is sealed off by walls but P2 can use the overflow bug to appear back on the map beyond the walls.

#  Fire temple

This challenge exploits the hardware bug where a transfer of 0 bytes results in 65k bytes being transferred: https://plutiedev.com/hardware-issues#dma-length-0

The NPC has a password to guess and it also renders the player's input text on the map (by DMA transfering it onto the plane B tile data). By providing a text of length 0 (pressing the backward button during text input), the 65k DMA upload triggers and uploads the empty text tiles and everything on the stack that comes after it, including the password, which will then be visible to the player.

# Water temple

The cartridge saves the current player positions on the given map of the given world upon resetting the console (either pressing the reset button or powering off+on). When the game is reset, players start from the same position they were occupying before but all map items get reset.

The path to the miniboss is blocked by 2 doors and the 2nd key on the map is blocked behind another door.
Players can get both keys as follows:
* Get key 1
* Use it to open door leading to key 2
* Leave a player outside the (now open) door and one inside it, wait for save
* Reset game - one player is not outside the closed door while another is inside
* Get key 2 with the inside player
* Exit area with outside player
* Navigate to and get key 1
* Use both keys to unlock the 2 doors leading to the miniboss

# Sky temple

A new "knife" item is introduced that, when equipped, doubles the player's damage dealt. When removed, the damage is halved again.
This round also introduces friendly fire for enemy projectile shots.

Players can combine the knife and "sword" item (that adds +1 damage and -1 when unequipped) to deal 0 damage:
Base damage: 1
Equip knife: 1 -> 2
Equip sword: 2 -> 3
Unequip knife: 3 -> 1
Unequip sword: 1 -> 0

They can then repeatedly hit enemies to move them around without killing them. Using this, they can position the archer to be in range to shoot the miniboss that can't be reached otherwise.

# Boss

The minions guarding the boss are as fast as the player and are invulnerable. They'd kill all 4 players before they'd have the chance to hit the boss enough times.
By coordinating the movements, 3 players can lure away the minions and soak up the damage from them while the 4th player walks up to the boss and hits it until it's defeated. There's also a Goggles item on the map that players can take turns wearing to extend their health and keep the minions busy for longer.
