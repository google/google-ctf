# Challenge Description

## Sandbox NamespaceFS

A remote filesystem with protobufs and namespace-based security. You can find
the flag at /home/user/flag (read-only by root)

# Details (warning: spoilers)

A sandbox challenge based on user namespaces.

You start out with a service talking protobufs that allows you to read/write files in a sandbox.

It will attach to a user namespace and set the fsuid to an unprivileged user that can't read the flag.

It only reads files from a given directory and checks before that there is not ".." in the path.

For the first step, you need to figure out that you can bypass the .. check with a null byte in the path. Then write to /proc/init/mem to get code execution inside of the sandbox.
This doesn't allow you to read the flag yet since you're running as the unprivileged user.
But you can use the same bug again to write to a uid\_map.
I.e. as the unprivileged user, unshare a namespace and make the supervisor write
a uidmap that gives you root. You can then setuid to root to read the flag.
