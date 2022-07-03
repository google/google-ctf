# sandbox-treebox

A simple Python sandbox challenge. Player can submit Python code, and that code
is then scrutinized by ast.walk(), which walks through each and every node of
the AST tree. If any call or import is found, the code is rejected. Otherwise
it's executed.

The flag is in `./flag` file - this is known to the player, as is the Python
version (or rather the OS and that Python is installed with apt-get).

There might be multiple solutions to this task, but the one I came up with is
in the `healthcheck/solution.py` file.
