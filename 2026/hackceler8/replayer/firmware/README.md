# Replayer firmware

This directory contains the firmware for the replayer used at Hackceler8 2026.
See the manual [here](https://github.com/google/google-ctf/blob/main/2026/hackceler8/plugins/Replayer%20manual.pdf).

## How to build

1. Set up a Zephyr development environment by following the instructions [here](https://docs.zephyrproject.org/4.4.0/develop/getting_started/index.html).

2. Download the secure boot signing key from [here](https://drive.google.com/file/d/12iCd_zqLKaXaZHNkC1plCc0Lwa-8EBjE/view?usp=drive_link&resourcekey=0-mtCEASkPFCxt2ZwOCxT-xw) and save it as `signing_private.pem` in this directory.

3. Run `cmake -Bbuild -GNinja .` to set up a build directory.

4. Run `ninja -C build` to build the firmware.

## How to flash

1. Connect the replayer to your computer via USB.

2. Press the RESET button on the board while holding down BOOTSEL. The replayer shows up as a USB drive called RP2350.

3. Drag and drop `build/zephyr/zephyr.signed.uf2` into the virtual USB drive.

## How to debug

When secure boot is enabled on the replayer the debug port is disabled at boot. If you want to debug the replayer, you need
to flash a debug firmware which re-enables the debug port when it runs. This project has a special debug configuration which
enables the debug port, turns on asserts and builds the firmware with additional debug info.

**DO NOT EVER GIVE A COPY OF THE DEBUG FIRMWARE OR A BOARD WITH THE DEBUG FIRMWARE FLASHED TO ANY OF THE PLAYERS, FOR ANY REASON**.

1. Run `cmake -Bbuild-debug -GNinja -DSNIPPET=debug_image .` to set up a separate build directory for a debug build.

2. Run `ninja -C build-debug` to build the debug image.

3. Press the RESET button on the board while holding down BOOTSEL. The replayer shows up as a USB drive called RP2350.

4. Drag and drop `build-debug/zephyr/zephyr.signed.uf2` into the virtual USB drive. 

You can now debug the replayer using a SWD debug probe. For example: `pyocd gdbserver --target rp2350`, then in another terminal `arm-none-eabi-gdb build-debug/zephyr/zephyr.signed.elf` and `target remote :3333`.
Or use another debug probe/client like probe-rs, J-Link, etc... You get the idea.

When the debug port is enabled you can also flash the firmware over SWD. In that case flash `build-debug/zephyr/zephyr.signed.elf`.

The firmware is set up to log exclusively to RTT. You can see the logs with something like `pyocd rtt --target RP2350` or `probe-rs attach --chip RP235x --protocol swd build-debug/zephyr/zephyr.signed.elf`.