# Note: you need to copy crypto_backdoor.py to this directory for this to work.
from crypto_backdoor import *

# The addition rule was created by adding a value 'd' as an extension to
# ingeters, with the rule that d^2 = 1.  If we use d^2 = -1, we get complex
# numbers, but this is a simpler ring.  The multiplication rule is derived from
# this equation:
#
# (x1 + d*y1)*(x2 + d*y2) = x1x2 + d*(x1y2 + x2y1 + y1y2)
#
# This results in the following addition law:
#
#   x3 = x1x2
#   y3 = x1y2 + x2y1 + y1y2
#
# Note that the rule for x3 does not depend on y1 or y2, so this is really a
# 1-dimensional addition rule, disguised as a 2D rule.  This allows us to easily
# convert it back to 1D (simply ignore y3) so we can use Sage's DLP solver over
# integer rings.  Next, two simple variable substitutions were performed to get
# our obfuscated addtion rule:
#
#   x' = x/y - 1
#   y' = 1/y
#
# Applying these variable substitutions result in the addition law used in the
# challenge.  To recover Alice's secret key from her public key, A, we just
# apply the variable substitution to map it back to to the simper 1D equation,
# and then solve for x with Sage's DLP solver.

length = 31
encrypted_message = 137737300119926924583874978524079282469973134128061924568175107915062758827931077214500356470551826348226759580545095568667325

# Map the generator and public keys back to the first equations above.
g2 = (g[0]*modinv(g[1], p) - 1) % p
print "g2", g2
A2 = (A[0]*modinv(A[1], p) - 1) % p
B2 = (B[0]*modinv(B[1], p) - 1) % p
# Now we just use a regular DPL solver on the X coordinate.  p is the multiple
# of a bunch of small primes of size around 1 billion.  This lets Sage solve DLP
# instantly.
aliceSecret = log(Mod(A2 , p), Mod(g2, p))
bobSecret = log(Mod(B2, p), Mod(g2, p))
print "aliceSecret =", aliceSecret
print "bobSecret =", bobSecret
# Now we need to compute the master secret shared betweeen Alice and Bob.
point = mul(aliceSecret, B, p)
masterSecret = point[0]*point[1]
# Finally, decrypt the message to reveal the flag.
print "Recovered master secret", masterSecret
message = Sn(encrypt(encrypted_message, masterSecret), length)
print "Decrypted message is", message
