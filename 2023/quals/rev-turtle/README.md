## Turtle

Participants receive two image files and a python script that checks if an entered flag is correct. The goal is to figure out how the script checks for the flag's correctness.

The script uses the python [Turtle Graphics](https://docs.python.org/3/library/turtle.html) library, normally used to code simple drawing programs using the [Logo](https://en.wikipedia.org/wiki/Logo_(programming_language)) programming language that movea pen-holding turtle around a canvas and make it draw shpaes.

In this script, however, the turtle behaves like a CPU: It first loads the `c.png` image (the code) onto the canvas, then goes through the canvas, reading each pixel it sees and interpreting it as an instruction. Depending on the instruction, the turtle modifies register values, reads/write memory or jumps to a different instruction (i.e. moves to another part of the canvas).

Apart from the CPU turtle, there are 3 more turtles for reading/writing the registers, memory, and stack (which is separate from the regular memory here). Registers and the stack all start initialized to 0 while the initial memory layout is loaded from the `m.png` image.

Apart from the regular mov/lea/cmp/add/jmp/call/ret instructions, there's also a "fail" and "success" instruction that make the program print out "Correct/incorrect flag" and exit. If the competitor managed to input the right flag, the CPU turtle will eventually execute the "success" instruction.

The code contained in `c.png` is a crackme that the competitors have to reverse (see `src/crackme.cc` for the original C++ source code). It has 3 functions (hence the 3 columns of varying length in the image): The main entry point, a helper function to sort the flag, and a recursive implementation of binary search.
The crackme checks for the correctness by first verifiying that each char of the flag only appears once. Then it sorts the flag's characters by relocating the using a predefined "sort index array". Finally, it goes through the characters `'+'` through `'z'` runs the recursive binearch on each char and the sorted flag. During every iteration of the binary check, it verifies that the comparison result is the same as indicated in a hardcoded comparison array. If all comparisons went as expected (which can only happen for the correct flag), the checker returns "success".

See `src/rev.cc` for one way to figure out the flag once the crackme code has been reversed.
