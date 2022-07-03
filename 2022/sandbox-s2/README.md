Sandbox S2
==========

This runs user provided payload in Sandbox2.

Due to misconfiguration it is possible to install another seccomp policy and handle the user notify for it.\
As USER_NOTIF takes precedence over TRACE one can allow any syscalls that are trace'd in Sandbox2.\
Sandbox2 traces all syscalls where syscall architecture does not match, so it is possible to execute all syscalls using 32-bit mode.

execveat (with some magic args) is traced in the policy, so it's possible to call, but there is no way to produce the 32-bit binary.
One can however directly switch to 32-bit mode, updating the cs appropriately.
