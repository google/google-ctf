# Memsafety

Challenge will exploit https://github.com/rust-lang/rust/issues/80895 -- a proof-of-concept is available at https://godbolt.org/z/MzWjfnvoc.

The scenario such that users can provide a snippet of Rust code which will be compiled into a program vulnerable to the above issue. We'll write a simple parser to check/constrain the code users provide, although defeating the sandbox to get RCE will also be considered a solution (although not the intended one). The flag will reside in memory, with the intended solution being that the heap overflow is used to search memory for the flag.
