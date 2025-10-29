# Solution

See healthcheck and/or challenge directory for solver.

The bug is that you can first leave the STEP open (without
matching ENDSTEP), which allows you to later add ENDSTEP
without matching STEP - and that pushes internal stack pointer
to an invalid region (-1 etc.).
