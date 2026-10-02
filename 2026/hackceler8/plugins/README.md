# Recording plugins for scripted input

Record a solution:

```
RECORDING=my-solution.mlen mame genesis -cart hx8.md -autoboot_script plugins/record.lua
```

Replay a solution:

```
REPLAY=my-solution.mlen mame genesis -cart hx8.md -autoboot_script plugins/replay.lua
```

The emulator pauses after the recording finishes - press 'P' (or the configured MAME shortcut) to unpause

Replay a partial solution and record into a new file (keep playing after the recording finished to append to the new recording):

```
RECORDING=my-wip-solution-2.mlen REPLAY=my-wip-solution-1.mlen mame genesis -cart hx8.md -autoboot_script plugins/replay-record.lua
```

# Converting to the replayer hardware's format

See plugins/example.py and the replayer hardware manual.
