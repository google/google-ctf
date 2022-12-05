uBASIC: a really simple BASIC interpreter
=========================================

http://dunkels.com/adam/ubasic/

Written in a couple of hours, for the fun of it. Ended up being used in a bunch of places!

The (non-interactive) uBASIC interpreter supports only the most basic BASIC functionality: if/then/else, for/next, let, goto, gosub, print, and mathematical expressions. There is only support for integer variables and the variables can only have single character names. I have added an API that allows for the program that uses the uBASIC interpreter to get and set BASIC variables, so it might be possible to actually use the uBASIC code for something useful (e.g. a small scripting language for an application that has to be really small).

See the file `use-ubasic.c` for an example of how to use it.
