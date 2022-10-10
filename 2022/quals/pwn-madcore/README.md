# Coredump handler challenge (madcore)
This was intended to be a privesc challenge, but due to time constraints, is a
standard networked challenge.

## Design
The challenge takes a corefile, parses some info, tries to recover a stack trace
and symbolicate the frames using llvm-symbolizer.

## Vulnerability / exploit
While there are probably lots of bugs in this code, the ones that I intend to
use to be exploiteded:
  - std::optional set to std::nullopt (aka uninitialized memory)
  - Out of bounds read/write due to the std::optional
  - Arbitrary file read using llvm-symbolizer

Crafting the right coredump should enable you to control the uninitialized
memory in the std::optional, setting rsp to garbage should allow you to get an
empty Backtrace object, and then setting up the registers right in the oob-write
should allow you to control an argument to llvm-symbolizer. You can use this to
read a file that the coreparser should print out to you later on. :)
