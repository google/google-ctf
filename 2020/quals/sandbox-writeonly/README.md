# Challenge Description

## Sandbox Writeonly

This sandbox executes any shellcode you send. But thanks to seccomp, you won't be able to read /home/user/flag.

# Details (warning: spoilers)

This challenge is intended as a beginners challenge and should be solvable
without too much time investment by experienced players.

The setup is as follows:
* the challenge reads shellcode from the user
* forks a new process
* child:
  * sleep indefinitely
* parent:
  * set up a seccomp filter that doesn't allow reading
  * executes the shellcode of the player

The intended solution is to inject code into the child.
I.e. opening /proc/childpid/mem, seeking to the right address and writing 2nd
stage shellcode that reads the flag.
