#!/usr/bin/env bash
# Create virtualenv
if [[ ! -d .venv ]]; then
    virtualenv .venv
fi;

# Activate virtualenv and install requirements
source .venv/bin/activate
pip install -r requirements.txt

exec /usr/bin/env bash
