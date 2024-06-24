# Game Arcade

### Running the solver

Simply run `python3 solve.py` and it should output a flag.


### Write-up

There is a Guess the Password game that should render on the
`https://0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog`
origin. Because of a bug in SafeContentFrame, it's possible to bypass the hashing
check for a site and set cookies on
`0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog`
from `<poc_hash>.0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog`.

Admin's flag is stored in a cookie and it's also the source of an XSS.
