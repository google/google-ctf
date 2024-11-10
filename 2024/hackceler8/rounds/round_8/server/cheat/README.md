# Modified client for easier playtesting

This is a modified game client with some minimal cheats added that can make playtesting challenges easier. Competitors will likely make similar or better mods to their own game.

This client works like the normal client except it allows
* Adjusting the game speed
* Recording and replaying playthroughs

## How to start

1. Follow the README in the project root.

2. Instead of `python3 client.py`, run `python3 -m cheat.cheat`.

## Controls

### Slowdown

* Slow down the game 2x, 3x, etc. by repeatedly pressing the down key
* Make it faster again with the up key

### Frame by frame advancement

* Switch to frame-by-frame mode by pressing backspace
* Exit by pressing backspace again
* Advance the game 1 frame with the right key
  * Whichever keys are pressed during the advancement will be the ones processed by the game's tick.


### Record and replay gameplay

* The client automatically saves your gameplay into cheat/keys_{getpid()}.txt
  * The game is saved every 20 frames or whenever the player dies
  * The game is not saved while the player is dead
* To replay a previous gameplay, add `--replay=cheats/keys_{some ID}.txt` (modify the key file as needed)
* To stop the replay 60 frames (1s) before the end of the file, add `--stop-replay-before=60`
  * e.g. if you died on a previous gameplay, you can reset your position 2s before your death with `python3 -m cheat.cheat --replay=cheat/keys_{some ID}.txt --stop-replay-before=120`
