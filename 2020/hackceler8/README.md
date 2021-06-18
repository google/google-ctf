# Hackceler8 2020

**Important**: While the code and some art are on Apache 2.0 license, other art is not (i.e. some art cannot be redistributed with e.g. forks of this project without acquiring a license; good news is that you'll be supporting indie game artists on itch.io if you do choose to do that). See LICENSE file in game subdirectories for details.

**Disclaimer**: This isn't an official product. It's a highly experimental CTF-like idea implemented by a couple of engineers in a couple of proverbial evenings. Expect errors, bugs, and problems.

This directory contains all 6 versions of the competition platform (speed-hacking game) used at Google CTF 2020 Final Event aka Hackceler8, including the "pre-tournament" version shared with the competing teams a week before the tournament.

See [Google CTF Hackceler8 website](https://capturetheflag.withgoogle.com/hackceler8) for more details.

To play the game you'll need docker and docker-compose (can be on a Linux VM), and a browser (tested mostly on Chrome). Just enter any `match-*` subdirectory and type:

`docker-compose up --build`

After the game is running, connect with the browser to `http://127.0.0.1:4567/` (or whatever IP the Linux VM you are using might have) and use **player**/**asdf** as credentials.

**Important**:  This setup is usable for testing only. Don't use this to run
competitions! Check out [KCTF](https://github.com/google/kctf) instead.

During the tournament setting players had access to the source code of both the client and the server side of the game, but did not have access to source code of the challenges (nor obviously to the flags). Any client-side game glitching / hacks / mods / http proxies / etc were allowed (and actually required to complete some challenges) - do note that there is an anti-cheat which will block some obvious stuff.

If you're wondering how does the game work - well, that's something the players had to figure out during the competition as well, so... good luck! :)

Hint: Use [Tiled](https://www.mapeditor.org/) for viewing the map.

## Known issues

* See README.md file in `match-*` subdirectories.
* Server-side saving of game state is disabled - if you want to re-enable it, check `game_service.js` and look for `/tmp/state_` - there's a comment there explaining what to do. Afterwards you can run the game (`main.js`) with the state file as an argument to recover the state.

## Project Credits
In somewhat random order.

Gynvael Coldwind<br>
*Project Lead, Game Developer*

jvoisin<br>
*Project Lead, Commentator, Challenges Writer*

scrinzi<br>
*SRE*

Nicolas De Sola<br>
*Design & Creative Direction*

Hlynur<br>
*Music, Commentator, Challenges Writer*

Calle Svensson<br>
*Video production, Commentator*

ddmassey<br>
*Commentator*

Ian Eldred Pudney<br>
*Game Developer, Challenge Writer*

Ollie Green<br>
*Commentator*

spq<br>
*Challenge Writer*

Pei Si Tan<br>
*SRE*

acskurucz<br>
*Avid Listener & Random Support, Tester*

akrasuski<br>
*Challenge Writer, Tester*

Paul Dev<br>
*Super Hackceler8 Maker user*

Jan Keller<br>
*Enabler of Things*

And others!