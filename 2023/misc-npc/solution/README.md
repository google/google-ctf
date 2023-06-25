This is an implementation of:

> We take some NPC problem (say: Hamiltonian path, with letters on the edges)
and say that the password is the solution to this problem, but also a valid
sentence in English. The combination of the two constraints makes the problem
space small enough to search efficiently and find the password. I think we can
do this with most of the NPC problems (e.g. SAT should be doable, SUBSET-SUM as
well), so if there is one that we would like to pick I can think about
phrasing it in this way :)

The word list is the words used in US constitution from a public domain word
list set (https://www.gutenberg.org/ebooks/3201), specifically
https://www.gutenberg.org/files/3201/files/USACONST.TXT.

All the scripts are using
[`pyrage` library](https://github.com/woodruffw/pyrage) for encrypting files.
The easiest way to get it is with `pip` (`python -m pip install pyrage`), here
is how to do it in a virtual environment on a Cloudtop:

```
# Workaround for https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1026268
$ sudo apt-get install python3-venv

# Create a virtual env:
$ python3 -m venv /tmp/sandbox

# Activate the virtual env in this shell:
$ source /tmp/sandbox/bin/activate

# Install pyrage in the virtual env:
$ python3 -m pip install pyrage
```

How we could use that to generate a challenge?

1.  Choose password length `N` (the solver can solve the example below which
    uses `N=5` in < 2 minutes, but another one I tried with `N=6` took >40h;
    `less_brute_force.py` took >40h for `N=5`, `brute_force.py` takes forever).
2.  Run `python3 encrypt.py N 'The secret to be encrypted'`
3.  Give `encrypt.py`, `hint.dot` and `secret.age` to the contestants (maybe
    also `USACONST.TXT`, but I think it's easy to find this file online).

Example (actually used to generate the files):

```
$ python3 encrypt.py 5 'CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}'
Your secret is now inside password-protected file secret.age.
Use the password standardwatersigngivenchosen to access it.
In case you forgot the password, maybe hint.dot will help your memory.

# This is the rendered hint: https://graphviz.corp.google.com/image?graph_id=275ed3225b5a97dd70d98381217b1d65
# (this does not get printed, I included it here as a comment for convenience).

$ python3 -c 'import pyrage.passphrase; print(pyrage.passphrase.decrypt(open("secret.age", "rb").read(), "standardwatersigngivenchosen").decode("utf-8"))'
CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}

$ python3 solver.py
Trying 0th password: chosenstandardsignwatergiven
Trying 1th password: chosenstandardwatersigngiven
Trying 2th password: givenchosenstandardsignwater
Trying 3th password: givenchosenstandardwatersign
Trying 4th password: givenstandardsignwaterchosen
Trying 5th password: givenstandardwatersignchosen
Trying 6th password: signchosenstandardwatergiven
Trying 7th password: signgivenchosenstandardwater
Trying 8th password: signgivenstandardwaterchosen
Trying 9th password: signwatergivenchosenstandard
Trying 10th password: standardsignwatergivenchosen
Trying 11th password: standardwatersigngivenchosen

The password was standardwatersigngivenchosen
The secret is: CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}

$ python3 less_brute_force.py
(doesn't finish anytime soon)

$ python3 brute_force.py
(doesn't finish anytime soon)
```
