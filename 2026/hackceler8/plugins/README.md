# Recording plugins for scripted input

This version of the plugin provides a way to replay and record traces in a
single plugin. It supports two replay file formats, one designed to be used by
the hardware replayer and the other being the raw recorded trace.

## File formats

Files with `.nspace` extension are interpreted as the multi-stage format
supported by the hardware replayer. This format can be only used for replays and
it is the default format the replayer will expect when the input file is not
explicitly specified. For more details see the hardware manual of the replayer.

NOTE: the plugin does not simulate the wait for reset and this flag is currently
simply ignored.

In addition to it the plugin supports replaying and recording the raw traces in
the `.mlen` format, which stores key frames and the bitmask of pressed buttons.
This is the only format that the plugin supports as the output. For
implementation details see `write_frame` function in `main.lua`.

When the `.mlen` file is specified as an input the plugin will interpret it as a
single-stage `.nspace` file, which means that it can be replayed and appended to
without conversion.

## Replay

The plugin automatically starts in the replay mode when a filename specified in
the `REPLAY` environment variable or the default file `input.nspace` exists.

At the beginning it presents the user with the menu to select the trace to
replay. After selecting the trace, the dialog can be closed by picking the
"Close menu" option or by pressing `ESC`.

The replayer then proceeds to replay the trace and then advances to the next
stage of the `.nspace` file. Once the first trace is finished, the familiar menu
will appear again.

After all stages have been replayed, the emulator pauses and switches to the
record mode. Press 'P' (or the configured MAME shortcut) to unpause and begin
recording.

Example:

```text
REPLAY=my-solution.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua
```

## Recording

NOTE: when a recording with the default filename exists, the replayer will
atomatically pick it up and replay it before switching to the record mode.

The plugin can reach the record mode in two ways:

- the specified input file doesn't exist;
- the plugin has replayed all stages of the recording.

In the first case the recording will begin immediately and will continue until
the emulator is closed. The output will be stored in the filename specified in
the `RECORDING` environment variable or otherwise in the `output.mlen` file.

In the second case the plugin will replay all stages first and then will begin
recording a new stage after the user unpauses the emulator.

Example:

```text
RECORDING=my-solution.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua
```

## Extending a recording

In addition to recording new stages the replayer also supports extending the
last stage of the existing recording. Note that it will still be recorded as the
`.mlen` output file. This behaviour can be enabled by setting the
`EXTEND_LAST_STAGE` environment variable to `true`.

Replay a partial solution and record into a new file:

```text
EXTEND_LAST_STAGE=true RECORDING=my-wip-solution-2.mlen REPLAY=my-wip-solution-1.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua
```

## Converting to the replayer hardware's format

See plugins/example.py and the replayer hardware manual.

## Example workflows

### Record a single-stage solution

* Record first part:
  * `RECORDING=wip-1.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua`
  * Start playing, then exit emulation
* Amend first part with more playthrough
  * `EXTEND_LAST_STAGE=true RECORDING=wip-2.mlen REPLAY=wip-1.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua`
  * Select stage A on startup
  * Wait for replay to finish and the game to pause
  * Unpause and continue playing to record second half
  * wip-2.mlen now contains the full playthrough.
* Convert to a 1-stage .nspace file that starts on reset: Modify plugins/example.py with
```
from builder import File, Stage, Replay, TraceFlags

with open("../my-solution.nspace", "wb") as f:
    r = File([Stage(a=Replay("../wip-2.mlen", flags=TraceFlags.WAIT_FOR_RESET))])
    f.write(r.build())
```
* Try on emulator:
  * `REPLAY=my-solution.nspace mame genesis -cart hx8.md -autoboot_script plugins/main.lua`
  * Select branch A for stage 1 in the menu
  * Wait for replay to finish
  * Exit emulation
* Try on hardware:
  * Load my-solution.nspace onto replayer filesystem
  * Press A to queue the only branch of the only stage
  * Press reset on the console to start the replay

### Record a multi-stage multi-branch solution

* Record first, single branch stage:
  * `RECORDING=stage-1.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua`
  * Start playing, then exit emulation
* Record second stage with 2 branches:
  * `REPLAY=stage-1.mlen RECORDING=stage-2a.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua`
  * Start playing, then exit emulation
  * `REPLAY=stage-1.mlen RECORDING=stage-2b.mlen mame genesis -cart hx8.md -autoboot_script plugins/main.lua`
  * Start playing, then exit emulation
* Assemble into a branched .nspace file: Modify plugins/example.py with
```
from builder import File, Stage, Replay, TraceFlags

with open("../my-solution.nspace", "wb") as f:
    r = File([Stage(a=Replay("../stage-1.mlen", flags=TraceFlags.WAIT_FOR_RESET)), Stage(a=Replay("../stage-2a.mlen"), b=Replay("../stage-2b.mlen"))])
    f.write(r.build())
```
* Try on emulator:
  * `REPLAY=my-solution.nspace mame genesis -cart hx8.md -autoboot_script plugins/main.lua`
  * Select branch A for stage 1 in the menu
  * Wait for replay to finish
  * When the menu comes up again, you can select either branch A or B
  * Wait for replay to finish
  * Exit emulation
* Try on hardware:
  * Load my-solution.nspace onto replayer filesystem
  * Press A to queue the only branch of the 1st stage
  * Press reset on the console to start the replay
  * During the replay of stage 1, press B on the console to queue branch B of stage 2
  * Once stage 1 has finished, branch B of stage 2 will automatically play
