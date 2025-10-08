# Forest temple

Heal tiles are introduces that can give a player back 1 health but can only be used once per world. Players need to press switches that deal damage to them - without using the heal tile multiple times they can't press all of them.

There's a bug in physics.rs try_move where if the player tries and fails to move diagonally, it returns the tiles the player hit before the x alignment. This is the tileset that's used to check if "should heal" should happen. The check for "should heal tiles deactivate" happens with the tiles computed after alignment. Thus, if the player stands on the edge of a wall next to a heal tile and moves diagonally, they'll get healed without spending it, allowing them to get healed infinite times.

Another (unintended) solution found by teams during the competition: All players can get healed once if they all trigger the heal tiles in the same frame. Additionally, players don't get damaged on the heal tiles if their state is already "damaged", e.g. if they just got hit by an enemy when standing on the tile. Players can use the enemies on the map to get hit at the right time and only lose 1 health instead of 2. Combined with the one-time healing applied to all players, players will have just enough health to open all 3 sets of switches. This is much more difficult to input manually than the intended solution though.

#  Fire temple

The dialogue logic is changed to allow text input that overflows past the B plane and into the sprite buffer in the VRAM.

The way to the miniboss is blocked by 5 gates. To get 5 keys, the player must open 5 of 10 chests, the other 5 being mimics that kill the player.

The mimic locations are randomized on every try but they're always last in the sprite render order. The player can use the VRAM overflow bug to spam the sprite buffer until they overwrite the first sprite's NEXT pointer. They can then cycle the text input's printed letter until they land on a letter whose tile ID sets the NEXT pointer to the place of the first mimic in the sprite buffer.

This way the true chests will not be rendered on the screen during the rest of the dialogue, allowing the player to figure out where they are and get the keys without dying.

# Water temple

The path leading to the miniboss can be unlocked by pressing the 4 switches on the map with the correct player 6 times in a row. The correct player for a given switch in a given round can be figured out from the somewhat-obfuscated code in switch.rs

Players have 4 seconds to press the next switch, and they're not allowed to pause the game while the minigame is ongoing. 4 seconds is enough to comfortably get into position if you only need to focus on one of the players - so competitors will need to have all 4 team members at the controller to solve this challenge.

The correct solution (which player needs to stand on which switch in a given round):

```
Round 0:
 2
3 0
 1

Round 1:
2 1

0 3

Round 2:
 3
2 1
 0

Round 3:
0 3

1 2

Round 4:
 0
2 3
 1

Round 5:
0 2

1 3
```

# Sky temple

When all 4 players stand in a row on a specific map (checked by looking for the presence of the snake NPC), a warning dialogue is shown before projectiles spawn.

The check that triggers the dialogue is run even when the game state is MapSwitch, allowing the player to trigger it during the transition by making all 4 players exit the map in a row.

Once the dialogue finishes the game state will return to Idle, allowing the player to move in a half-transitioned map where the door that blocked the path to the miniboss has been pushed aside.

# Boss

After every 4 hits to the boss, the player is sent back to the entrance and a random map layout is selected with 1 out of 5 paths leading to the boss and the other 4 leading to spikes.

The screen also gets progressively darker and the last 4 map layouts are in complete darkness, giving the player only a 1 in 5^4 chance of correctly getting to the boss.

There are also color tiles on the boss map that tint the palettes in a certain color when stepped on, including the BG color. The BG color is tinted even when it's fully dark, so players can look at the tint pattern to figure out which layout is loaded and how to get to the boss.

Most emulators don't show the BG color in itself but when running the game on the console it'll appear as the overflow color on the display.
