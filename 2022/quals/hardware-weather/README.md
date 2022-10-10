# Weather (Hardware)
Blame: gynvael@

Note: Challenge is ready for open-sourcing.

## Challenge overview
In this hardware challenge the player gets access to a small IoT Weather Station.
Players also get:

  * its firmware source code (but NOT the binaries),
  * high-level design schematics,
  * and some documentation for various pieces.

The players can also interact with the challenge's stdin/stdout by connecting to a given IP/port. Using the built-in menu, the player can read/write to selected I2C devices - i.e. read temperature sensors, humidity sensors, light sensors, etc.

The end goal - which is communicated to the player - is to read the content of an EEPROM, which is operated via MMIO (it is not connected via I2C).

For solution (containing spoilers) see [solution.md](solution.md).

