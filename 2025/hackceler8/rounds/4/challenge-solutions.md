# Forest temple

A property is added for enemies that periodically slow down the players. The player speed is reset to its proper value each time a new map is loaded.

Part of the map is inaccessible as it is blocked off with walls.

By repeadetly equipping boots while being slown down and unequipping it after being sped up again, a player can get a very high speed, allowing them to clip through walls.

#  Fire temple

There's a narrow corridor leading to the miniboss guarded by flamebois who shoot down. Players cannot avoid the projectiles.
By walking with 3 players in a row (and equipping the front players with goggles), P2-4 can soak up damage for P1, allowing the last player to get to the miniboss without being killed.

# Water temple

A one-time use "staff" item is introduced that shoots fireballs. Once the player shoots the fireball the item disappears from the inventory when the attack state finishes and returns to idle.

However, if the player gets hit while the attack state is actice, the state will be interrupted and the item is kept, allowing the player to shoot multiple fireballs.

The miniboss is on a cliff that can't be reached but the player can exploits the above bug to shoot it from afar with the staff multiple times.

Another (unintended) solution that teams found during the competition is to unequip the staff, equip it to a different player, and shoot with it again before the first player's animation returns to "idle".

# Sky temple

The off-screen check is removed from arrows, allowing them to move to other maps. Additionally, friendly fire is introduced where enemies can shoot other enemies.

To defeat the miniboss that's out of reach, the player has to switch from the previous maps that contains archers while their arrow moves through the border, allowing it to be transported to the next map and shoot the miniboss.

# Boss

The boss is surrounded by flames that keep being regenerated. There's a 1/6th chance of a "fake" flame randomly appearing which doesn't damage the player.

Fake flames look the same as regular flames but use a different palette ID. Players need to use the CRAM overflow bug to rewrite the colors of the fake flame so they can tell them apart from the real ones and know where to stand to be able to hit the boss.

The CRAM overflow bug:

In the boss map there's a pencil that allows the player to color tiles similar to the Piet challenge from last year. The last 8 empty slots of the boss map palette are used as storage for the colors, as well as the last few unused tiles of the boss tileset.

When a new color is painted, either an existing unused slot is reused or a new slot is allocated. There's no length check, so if the player has more than 8 colors on the map, the next color to be added overflows into the next palette, which is the enemy sprite palette used by the real+fake flames.

By adding 10 or so different colors to the screen the player can overwrite some palettes of the fake flame and tell it apart from the real ones.

**Note:** As it turned out during the competition, the intended solution for this challenge doesn't work on the console because the "read from CRAM" register setting doesn't do anything on a real console - it only works on some emulators. However, the challenge can still be solved. One option is to brute force the location of the fake flame - if all 4 players hit the boss at the same time one only needs to get lucky once or twice in a row. Another solution is to add 10 of the first color onto the map - Since the CRAM read returns a random u16, the game will think the first color has not yet been used and allocates a new palette position for it.