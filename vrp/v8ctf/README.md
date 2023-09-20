# v8CTF challenge

This challenge is part of the v8CTF, an exploit VRP for the v8 JavaScript engine.

You can reach it at `nc v8.ctfcompetition.com 1337`.

It runs a `chrome --headless=new` on a user-provided URL. You can find the command line in chrome/challenge/chal and the Chrome version in chrome/challenge/Dockerfile.

The flag is at /flag/flag and is in the format `v8CTF{.*}`.

If you want to recreate the environment locally, check out https://google.github.io/kctf/ for tips on how to use the kCTF infrastructure.
