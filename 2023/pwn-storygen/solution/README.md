# Google CTF 2023 - pwn: storygen writeup

In the challenge, we are given a Python script running on the specified host and port. When we connect, we see:

```
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
> Adam
Where are you from?
> US
Do you want to hear the personalized, procedurally-generated story?
> yes

Adam came from US. They always liked living there.
They had 3 pets:
- a cat named Luna
- a cat named Bella
- a dog named Luna

Well, I'm not a good writer, you can write the rest... Hope this is a good starting point!
If not, try running the script again.

Do you want to hear the personalized, procedurally-generated story?
> no
Bye!
```

It's a silly story generator. We can ask for it to generate the story again, and it'll randomize the pet names etc. while keeping the provided answers. If we take a look at the Python code, we see it actually creates a shell script with variables being substituted by our answers. They are inside single quotes though, and single quotes themselves are stripped from our input.

We notice however that the script starts with one unquoted appearance of our variable:
`#@NAME's story`

It looks like it is inside a shell comment, and since we cannot use newlines, we cannot break out of it. However, we remember the hash sign in the first line can also start a shebang, like:
`#!/usr/bin/env python3`

We can use a name like `!/usr/bin/cat<space>` to make the script write itself, or something like `!/usr/bin/python3 -cprint(123)#` to execute Python commands. `/flag` file says the actual flag is found by executing the "/get_flag Give flag please" command, to prove we have arbitrary code execution. One way to accomplish this is, using pwntools:

```
r.sendline('!/usr/bin/env -S bash -c "/get_flag Give flag please" \\\nwherever\nyes\nno\n')
```

We use env command's -S option to split the rest of the shebang as though it was a shell command (by default, shebang only splits up to one parameter).

The flag is: `CTF{Sh3b4ng_1nj3cti0n_ftw}`
