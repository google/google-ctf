The bug is in formal verification - consider what happens if we have an
inconsistent circuit, e.g. a = b nand a -> which is okay when b is False
(a = True then), but when b is True, we have a contradiction. Z3 says unsat,
but it doesn't mean it proved the circuit correct, just that it found itself
in a contradiction.
