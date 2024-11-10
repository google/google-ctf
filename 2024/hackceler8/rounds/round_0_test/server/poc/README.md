# Collection and helper for reproducible proof of concepts

The collection automates challenge solutions to ensure it is still working
since our engine evolves pretty fast.

## Steps to run the PoC

1. Follow the README in the project root.

2. Instead of `python3 client.py`, run `python3 -m poc.poc_example`.

## Tips for writing PoC

If the action is static and simple, you can simply enqueue all the keystrokes
before starting the game.

The `ReplayHelper().start_game` function takes an iterator function, it gives
more flexibility on synchronizing keystrokes and writing assertions.
See `poc_example.py`.

For more complex exploits, you can inherit the `ReplayHelper` class, and
overwrite the callbacks for custom logic. Game states can be inspected using
`self.game` in those callbacks.

When the bug depends on the tick number, `self.last_queued_tick()` can help
you build the PoC.

Assertions can be written in the `on_replay_finished` callback.

## Interactive recorder for building PoC

Run `python3 -m poc.record`.

Keys recorded so far will be reported on the console every two seconds.

To start from a different map, add `--map=ruins`.
Make sure to add `replay.enter_map("ruins")` to your PoC script too.

To start from a different position on the given map, add `--pos=123,456`
(x,y). You can look up the position you want to go to on the map in Tiled.
Make sure to add `replay.teleport(123, 456)` to your PoC script too.

To make the game run 2x slower during replay, add `--slowdown=2`.

To reset the log, hold 'r' for at least one second.

## TODO BEFORE RELEASING TO PLAYERS:
Remove this folder.
