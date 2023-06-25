# Google CTF 2023 - RE: Zermatt writeup

*Note: this writeup was created by a challenge tester during our internal test run*

In the task we got a long file full of LUA code. When executed it prints:

```
$ lua code.lua 
 _____             _     ___ _____ ____ 
|   __|___ ___ ___| |___|   |_   _|  __|
|  |  | . | . | . | | -_| -<  | | |  __|
|_____|___|___|_  |_|___|___| |_| |_|   
              |___|       ZerMatt - misc 
> asd
LOSE
```

The code was all in one line, so we first beautified and indented it. We instantly see string obfuscation, e.g.

```
   local v8=_G[v7("\79\15\131\30\40\13\20\203","\59\96\237\107\69\111\113\185")]
```

This is a simple xor encryption, easy to reverse. Decoded, the line says:

```
   local v8=_G["tonumber"]
```

v8 is never updated, so replaced all its occurrences in file with simply tonumber (and similar for many other variables).

Another obfuscation is that there are constructions like:

```
                           local v124=0
                           while true do
                              if (v124==1) then
                                 v66=1
                                 break
                              end
                              if (v124==0) then
                                 v67=v62[998 -((2556 -1641) + 82) ]
                                 v68=v62[287 -(134 + 151) ]
                                 v124=1
                              end
                           end
```

There’s some useless arithmetics in the indexing, which we fixed using some Python and regexes.

The outer while loop is also useless, as it always executes the second if first, followed by the first one.
As v124 is not used anywhere else, we can reduce the code to:
```
                                 v67=v62[998 -((2556 -1641) + 82) ]
                                 v68=v62[287 -(134 + 151) ]
                                 v66=1
```
Or after fixing the constants:
```
                                 v67=v62[1]
                                 v68=v62[2]
                                 v66=1
```
Much more readable! I manually repeated a similar transformation for many while loops, as it was somewhat
difficult to automate it (there are a few variants, and treatment of nested loops is not always the same).

After an hour or so, we end up with a 387 line file (starting from around 1500 lines).
The file, as we can see, parses a long string constant using a rudimentary run length encoding.
There are several helper functions for taking bytes, dwords, doubles etc. from the stream.

At some point, I started adding prints to several of the variables to see what they correspond to.
It turns out that printing `A[2]` gives the flag: `CTF{At_least_it_was_not_a_bytecode_base_sandbox_escape}`.

Scripts used, and intermediate forms of the lua code, are available in this
directory.

