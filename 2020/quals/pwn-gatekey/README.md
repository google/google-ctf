# challenge description
Our data storage system is full of bugs. But luckily, you still cannot get access to the secret data somewhere in the middle of the 'flagdb' database, because we use gatekey protection (<https://lore.kernel.org/linux-api/20181029112343.27454-1-msammler@mpi-sws.org/>) to harden database access!
Note that this requires a kernel patched with the attached kernel patch, and it also requires a machine with very fancy instructions (and since almost nobody has those, we're just running the whole thing inside QEMU instead).
Sources, binaries (inside initramfs) and a pre-built kernel for use inside QEMU are provided.

# setup note
The parts provided to challenge participants are all in attachments/. (The challenge was published with source code provided.)
The only thing special about the version outside attachements/ is that the flag database embedded in the initramfs contains the real flag.

# exploit usage
exploit.sh will print a big amount of spew, the flag `CTF{...}` should appear somewhere in it.

# challenge author
Jann Horn
