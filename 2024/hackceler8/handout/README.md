# Hackceler8 2024 Game

## Steps to run the game:

1. Install prerequisites
```
cd handout
python3 -m venv my_venv
source my_venv/bin/activate
pip3 install -r requirements.txt
```

2. Run server (optional but good for testing cheat detection/etc.)

```
cd handout
source my_venv/bin/activate
python3 server.py
```

Note that this server is slightly different from the one run by organizers during the live rounds as it doesn't have all the code for the boss fights.

3. Run client

```
cd handout
source my_venv/bin/activate
python3 client.py
```

If you want to run the client without a server, pass `--standalone` as an additional argument.
