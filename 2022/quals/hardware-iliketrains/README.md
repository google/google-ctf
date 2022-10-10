# I Like Trains

This challenge is about reverse engineering a logic circuit in OpenTTD.
See https://wiki.openttdcoop.org/Logic for some details.

## How did this come together?
[minetest_pnr](https://github.com/google/minetest_pnr/) (with some
modifications) was used to generate a gate layout and a patched OpenTTD
instance then placed the actual relevant elements.

The underlying circuit multiplies two input numbers and verifies that they
match a constant. This constant is a product of two prime numbers so there
are only two numbers that satisfy this constraint. Additionally, checking that
the smaller number comes first guarantees that there is only one solution to
the circuitry.
