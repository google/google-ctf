### The Classic Notes App

A notes server with Async Mode MTE. There is a simple heap overflow but we have MTE!
What could be wrong if I have MTE? I don't care about memory safety now~!

### Exploit

It is Async Mode MTE, so it still allows you to write to an address before crash even if MTE violation.
Therefore, we can modify the memory to rename the string in the function frame structure.
First thing is to use UAF to find the address of a heap object.
Then you can use it to calculate the address of the function frame structure, but you cannot determine the flag.
Then you need to construct an overflow to modify notes array on the heap, so notes[0] points to the function frame structure.
You need to be lucky to perform the overflow. There is 1/16 chance that the heap object and function frame structure use the same tag.
Next, write to the notes[0] (which is the function frame structure now) and change "flag" to "exit"
