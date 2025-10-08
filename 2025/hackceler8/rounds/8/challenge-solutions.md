# Forest temple

The enemy vector capacity is decreased this round to 8, and the panics on vector overloads are replaced with regular info logging. This means that if there are already 8 enemies on the map the 9th one to be added will be discarded.

The miniboss is guarded by 2 enemies that kill the player before they can get to it. However, the player can prevent them from being loaded by carrying over enemies from the previous map. One solution:
* In the map with 3 enemies with a lot of health, make 2 fall down and hit the 3rd until its on the edge of the map. Then transition to the previous map along with the enemy.
* Transition back into the previous map along with the enemy as before. Now there are 4 enemies.
* Repeat one more time to make 7 enemies in total.
* Transition to the miniboss map. Only the miniboss will be loaded which saturates the enemy vec at 8 elements. The guarding enemies won't be loaded so the player can walk up and kill the miniboss.

There's also an unintended solution where players can lure the guardians away from a 3rd player that walks to the miniboss by standing closer to them through the walls.

#  Fire temple

To get to the miniboss, the player needs to walk through a bottomless pit that has an invisible randomly generated safe path through it.

Since it's fine for 3 out of 4 players to die, P1-3 can walk until they fall down, allowing competitors to figure out the path layout and get P1 safely across. The easiest way to complete this level with manual play is to let P1 and P2 walk in a row until P2 dies, then spawn P3 and continue, then do the same with P4. Players can also keep pausing and unpausing to slow the game and avoid the flames shot by the miniboss more easily.

# Water temple

Two bugs are introduced here:
* The logic to make the siren start singing is moved to player.rs and doesn't check that the current state is idle - thus a siren can move from Dying to Singing if the player walks up to it again.
* The player collision checks only run if the player moved - but not if the siren pulls the player.

The path to the miniboss is sealed with spikes. Players can use the siren's pull to move through the spikes unharmed. However, the siren is in a bad position for the pull to send players in the right direction. Players have to hit the siren to move it to the right position. Since the siren only has 3 healths, after the 3rd hit it starts dying and players have to trigger the singing state override bug to bring it back to life.

# Sky temple

The random mimics/chests from previous challenges are added here as well. To get to the miniboss, the player needs to get the 5 keys from the randomized chests (which use the same graphics as mimics but a different tileset).

A "bunifier" item is introduced that turns enemies into rabbits. It actually just switches their sprites with the rabbit sprites and sets "meele" and "flying" to false, making them harmless (unless they shoot projectiles).

The logic for adding the rabbit sprite uses custom code to load it into the next free spot and update the next position as normal. However, if there's not enough space, it will instead "saturate" and add it to the end of the VRAM, possibly overwriting other existing tiles that are near the end. In the sky level there are too many tiles to load together with the rabbit sprites if the player explores all of the dungeon.

By exploring the whole dungeon (loading many unique item/object tiles into VRAM) and going to the mimic map last (loading them to the end of the VRAM) then using the bunifier (loading the rabbit sprites, making it saturate and overwrite part of the mimic sprites), the player introduces a graphical difference between the mimic and regular chest sprites and can figure out which is which.

If the player uses the bunifier before exploring all of the dungeon, they'll trigger a BSOD when the last portion of the map is loaded.

Another (unintended) way to tell mimics and regular sprites apart is to lure other enemies onto the map with the mimics. If there are too many sprites in the same row, the VDP isn't able to render all of them. Since mimics always have the same indexin the sprite list, players can make them get a visual glitch with the right amount of sprites and figure out which chests are the real ones. This is much more difficult to input manually than the intended solution though because of having to pull enemies from other maps.

# Boss

The boss changes the layout of the map every 8s to make it full of bottomless pits in random positions. The randomness is determined based on the player positions and there are various corners on the map the player can stand in to have a precise repeatable position.

By standing in the corners at the right moments (a visual cue tells the player when they can stop standing in place) allows the player to know in advance how the map layout changes and how to avoid falling. After 8 layout changes 4 switches appear that allow the players to defeat the boss. Since all 4 players are needed to press the switch competitors need to make sure every player survives until the end.

There's an easier unintended solution: There's a bug in physics.rs try_move where if the player tries and fails to move diagonally, it returns the tiles the player hit before the x alignment. Thus if players stand in a corner and keep moving diagonally into the wall, the collision logic will think the player is not completely surrounded by bottomless pits. This way players can just camp in a diagonal corner for the duration of the 8 layout changes without needing to move around.