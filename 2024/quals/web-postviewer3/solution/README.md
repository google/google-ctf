# Postviwer v3

### Running the solver

Simply run `python3 solve.py` and provide a webhook URL. Please be cautios when
using an external services to not leak the flag unintentionally.

Specifically, **please do not use https://webhook.site**, as it's not safe.

https://app.interactsh.com/ seems to be a better alternative.

The solver by default doesn't send over the flag for security reasons.
See see the FAQ when it's appriopriate to run in a "leaking flag mode".

Note: The solver is not 100% deterministic, it might require multiple re-runs.

**FAQ**

1. Is challenge solvable?

To answer this question it's generally not needed to send back a flag. Peferer
running it in a default mode so that the flag doesn't accidentially get leaked.

2. Is flag correct? (Scoreboard doesn't accept)

If there is a doubt that a flag is not accepted, run the solver with `--flag`
option to make sure the outputted flag matches the scoreboard one.


### Write-up

Write-up in [solve.html](./solve.html).
