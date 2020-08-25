

# Exceptional

This pwn is a vm implemented using C++ exceptions. It is possible to
implement functions, loops and if statements this way, not the fully
generic goto though (not easily anyway).

Run the challenge by `make run`, or `make` and `./attachments/exceptional`.

# Spoilers

Inside the vm is implemented a timezone calculator with city-tz database
as a binary search tree (with hash of the city name as a key, for
both simplicity - the vm operates on 32-bit ints - and for obfuscation
of the exploit). The bug is that there is no balancing in the BST
and one can create a pathological case with most nodes creating
what is effectively a linked list. The search is implemented recursively,
which means the call will use O(cities) stack space, colliding the stack
with "heap", or rather with the tree node array, thus corrupting it.
The parameters are calculated so it's just barely possible to overwrite
the last few cities in the array, so it's unlikely to occur accidentally.
Overwriting the left or right pointer to point near the flag buffer
will reflect the flag in the output.
