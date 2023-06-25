# Solution

The JXL file is actually generated using JPEG XL predictors tree. AFAIK there is
no public tool to dump those, so the players will need to write it themselves
(the easiest way is probably to edit the libjxl code).

This will show players that every pixel is some function of neighbouring pixels.
After reverse engineering, they will see it calculates a sum of flag characters'
ASCII values multiplied by some constants, and comparing to another constant.
That's equivalent to a system of linear equations, which has algebraic solution.

The solution for this challenge is only partially implemented (in the second
part of `gen_eqs.py`, without actually parsing the JXL file).
