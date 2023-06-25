# Sandbox Lightbox

This runs user provided payloads in a custom namespace+seccomp sandbox.

It launches an init process in the pid_ns which has its own seccomp policy.
There is no synchronization between applying the policy to init and running the
payload. Using /proc/1/mem one RIP of init can be controled before the seccomp
policy is applied. To verify that players can circumvent the seccomp filter flag
is stored in an SySV shmem segment.
