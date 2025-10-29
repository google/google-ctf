# MegaRust

This challenge provides 2 flags, the second of which can be submitted in the misc-mega-rust-2 challenge's flag submission page.

The challenge consists of a small game written in Rust for the Sega Genesis / Mega Drive. The game has two flag items that can't be reached through normal playthrough. Competitors must find two bugs in the game to get the two respective flags. Once completed, they can submit their solution recordings to a checker running on the gCTF server and get the flag if their solution was correct.

## Spoilers ahead

To get flag A which is protected by spike enemies:
We can exploit the fact that the screen doesn't scroll when the player gets pushed away by an enemy. We can use that to get the flag that's guarded by the spikes: First we position ourselves so that most spikes are off-screen and get unloaded. Second we get hit by the wasp and sent backwards out of the screen, falling onto the flag since the spikes that protected it have been unloaded.

To get flag B which is too high up to jump to:
We can make use of the following game logic elements:
* The collision logic is based on the contents of the VRAM. The game loads whatever is displayed on the screen and considers non-0 Tile IDs to be solid tiles.
* The sprite data in the VRAM is close to the level background tile data so if we can cause 128 sprites to spawn we can corrupt the VRAM tile data and add some solid tiles that the player can walk onto to reach the flag.
* There's a logic bug in the wasp's loading and unloading code such that it's considered both on-screen and off-screen if it's x position is exactly on the edge of the screen, causing the game to spawn new wasps every frame if the player moves the screen the exact right amount of pixels.
Putting these together, we can reach the flag by moving to its location under the palm tree, standing such that the wasp spawn position is exactly on the right edge of the screen, wait 2-3s for it to spawn enough wasp sprites to overwrite the VRAM tile data, then move onto the corrupted tiles to reach the flag.
