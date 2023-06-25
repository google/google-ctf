# Solution

The code implements Langton's ant, a simple cellular automaton.
Langton’s ant is Turing complete (`http://www.dim.uchile.cl/~anmoreir/oficial/langton_dam.pdf`).
The initial pattern is actually a huge electronic circuit with additions, xors etc.

You need to reverse engineer the circuit (there are some dummy gates in the
unused cells), and then write the code to get the flag from the checked
conditions. Solution is in solver.py.
