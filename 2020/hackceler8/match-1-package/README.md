To run the game just use `docker-compose up` and connect to port :4567 with a
web browser.

Default username is `player` and default password is `asdf`.

**NOTE**: This setup is usable for testing only. Don't use this to run
competitions! Check out [KCTF](https://github.com/google/kctf) instead.

For licensing information check subdirectories.

### Known issues

Honestly there are many known issues as this was a purely experimental project
coded in a very limited time by just two people. But here are some major ones
anyway:

* If the browser's game tab becomes inactive, the game will not send any packets
to the local game server, but will try to send all packets it was supposed to
send the moment it becomes active. This actually might OOM the tab.
**WORKAROUND**: Just refresh the tab, no effective state is lost.
* In match 1 there are only 7 tasks, not 8 as the UI indicates.
