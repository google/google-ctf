# YouTube solves a CTF challenge

Also known as YouTube codes BASIC (among other things, we couldn't really decide
on the name).

Quick overview of the directory structure:

  * `composer` contains a small C++ app which puts the final frame together and
    streams it (using ffmpeg) to YouTube. It also handles terminal windows
    inside the frame.
  * `basic` contains everything related to the BASIC functionality, from the
    code that's writing to the BASIC terminal to the code which executes the
    8051 emulator with the BASIC interpreter.
  * `vote` contains all the code related to voting, from the YouTube bot, to the
    fancy real-time graph rendering in the voting terminal window.
  * `py_common` contains a few python libraries used both by `basic` and `vote`.
  * `third_party` contains code and resources made by others: uBASIC interpreter
    by Adam Dunkels, epto-fonts by EPTO, and NetSock (which was actually written
    by the author of this challenge before his Google times).
  * `clips` contains the few needed camera frames used in the challenge.
  * `common` contains a single file which you might want to populate with words
    you don't want appearing on the screen at any time.

If you want to see this challenge in action and don't mind SPOILERS, take a look
at this video: [A CCTV H4CK1NG G00GLE challenge](https://www.youtube.com/watch?v=v8zDNEeK0sU).
