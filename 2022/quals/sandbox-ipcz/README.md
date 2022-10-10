# sandbox IPCZ

IPCZ is the new ipc mechanism to be used in Chrome.

This challenge is set up as follows:
* a broker binary running as uid 0
* a flag\_bearer binary running as uid 0 and reading /flag
* flag\_bearer and broker communicate via ipcz. The broker asks for the flag, the flag bearer sends it.

The player can then send a binary that will be executed under uid 1338 (no access to the flag).

There's a custom patch to IPCZ that breaks it:
* the user can choose the node name for the sandboxee

Protocol details can be found in the [ipcz git repo](https://github.com/krockot/ipcz).
