# Solution for FixedASLR

This pwn challenge has implemented a custom .o dynamic (sic) loader, which loads
and links the object files at runtime. This allowed the implementation of a
custom ASLR (which spreads the .o files all over the memory), as well as custom
seeding for the stack cookie.

The actual challenge application itself is a simple game of adding numbers with
a scoreboard. The game has two bugs - both of which are somewhat hinted.

The first bug is a stack-based buffer overflow, though the return address is
protected with a stack cookie.

The second bug is a .data section buffer overrun which allows leaking 8 bytes
at a time from any place in memory. However since the addressing is relative,
it can't be used (yet) to read from an arbitrary absolute address.

The exploitation has several steps.

## Step 1. Mapping out the memory

Both the cookie and the ASLR were using the same LSFR PRNG, so before the cookie
can be defeated, one needs to get the LSFR state. And the only available way to
do it is to walk the dependencies of each .o file to gather at least 6
addresses (LSFR state is 64 bits; each known unique address leaks 12 bits of
state, so 6 are needed to get the complete state).

To start one can read the value of the `winner` pointer to get absolute address
of `main.o`. Having this, now one can turn the relative read-from-where to an
absolute read-from-where.

The `main.o` custom PLT table (which is at the front of the image) contains two
more pointers - one to `game.o` and one to `guard.o`.

The `guard.o` PLT contains a pointers to `syscalls.o`.

The `game.o` PLT contains a pointer to `basic.o`, and additionally one of the
data sections contains a pointed to `res.o`.

And that's the needed six.

## Step 2. Breaking the LSFR

After concatenating the bits in the right order (which can be determined by
analyzing `main.o`), one can do two things:

  * Roll it forward to get 12 bits revealing the address of `debug.o` (which has
    some useful ROP gadgets).
  * Roll it backward 72 times and read the state, which at that point is
    identical to the stack cookie value.

LSFR is reversible in a pretty simple manner, since all the information is known
to calculate the shifted-out bit to shift it back in (it's just a reversible XOR
after all).

## Step 3. Winning the game

Next step is to get at least 55 points in the game to get to be on the
scoreboard. Entering one's name is the exact place of the stack based buffer
overflow.

## Step 4. ROP

After winning the game it's a matter of using all the address information one
has to write a ROP that:

  1. Opens the `flag` file.
  2. Reads its contents into memory.
  3. Outputs it to stdout.

Alternatively one might want to get a shell.

That's it.
