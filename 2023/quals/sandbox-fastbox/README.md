# Sandbox Fastbox

This runs user provided payloads in Sandbox2.

It uses a custom forkserver, which leaks its comms FD to the sandboxee. Player
has control over a string arg passed in ForkRequest to the sandboxee. By racing
the custom forkservers read from Comms it can consume the ForkRequest prefix up
to the controlled string. That string can then be used to hold a "fake"
ForkRequest giving the launched sandboxee access to the flag file.
